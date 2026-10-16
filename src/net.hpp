#pragma once
#include "core.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <memory>
#include <stdexcept>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using sock_t=SOCKET;constexpr sock_t bad_socket=INVALID_SOCKET;
#else
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
using sock_t=int;constexpr sock_t bad_socket=-1;
#endif
namespace ws {
inline void closeSocket(sock_t s){if(s==bad_socket)return;
#ifdef _WIN32
closesocket(s);
#else
::close(s);
#endif
}
inline void shutdownSocket(sock_t s){if(s!=bad_socket)::shutdown(s,2);}
// The OS reason for the last failed socket call, named for the common cases (a reset is how some TLS clients reject a certificate).
inline std::string lastSocketError(){
#ifdef _WIN32
    int e=WSAGetLastError();switch(e){case WSAECONNRESET:return "connection reset by peer (WSAECONNRESET 10054)";case WSAECONNABORTED:return "connection aborted (WSAECONNABORTED 10053)";case WSAETIMEDOUT:return "timed out (WSAETIMEDOUT 10060)";default:return "socket error "+std::to_string(e);}
#else
    int e=errno;switch(e){case ECONNRESET:return "connection reset by peer (ECONNRESET)";case EAGAIN:return "timed out (EAGAIN)";default:return "socket error "+std::to_string(e);}
#endif
}
inline void nonblocking(sock_t s,bool yes){
#ifdef _WIN32
u_long mode=yes?1:0;ioctlsocket(s,FIONBIO,&mode);
#else
int f=fcntl(s,F_GETFL,0);fcntl(s,F_SETFL,yes?f|O_NONBLOCK:f&~O_NONBLOCK);
#endif
}
inline void socketTimeout(sock_t s,int seconds){
#ifdef _WIN32
DWORD t=DWORD(seconds*1000);setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&t),sizeof(t));setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&t),sizeof(t));
#else
timeval t{seconds,0};setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t));setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,&t,sizeof(t));
#endif
}
inline std::string socketAddress(sock_t s,bool peer){sockaddr_storage a{};
#ifdef _WIN32
int n=sizeof(a);
#else
socklen_t n=sizeof(a);
#endif
if((peer?getpeername(s,reinterpret_cast<sockaddr*>(&a),&n):getsockname(s,reinterpret_cast<sockaddr*>(&a),&n))!=0)return {};char host[NI_MAXHOST]{},port[NI_MAXSERV]{};if(getnameinfo(reinterpret_cast<sockaddr*>(&a),n,host,sizeof(host),port,sizeof(port),NI_NUMERICHOST|NI_NUMERICSERV))return {};return endpoint(host,uint16_t(std::stoi(port)));}
struct Channel {
    sock_t socket=bad_socket;SSL* ssl=nullptr;std::string buffer;
    Channel()=default;Channel(const Channel&)=delete;Channel& operator=(const Channel&)=delete;
    ~Channel(){reset();}
    void reset(){if(ssl){SSL_free(ssl);ssl=nullptr;}closeSocket(socket);socket=bad_socket;buffer.clear();}
    int read(char* data,int n){if(!ssl){int r=int(recv(socket,data,n,0));if(r<0)throw std::runtime_error("Read failed: "+lastSocketError());return r;}
        int r=SSL_read(ssl,data,n);if(r>0)return r;int e=SSL_get_error(ssl,r);unsigned long code=ERR_peek_error();
        // close_notify, a bare TCP close, or OpenSSL 3's "unexpected eof": the peer is gone, same EOF as before.
        if(e==SSL_ERROR_ZERO_RETURN||(r==0&&e!=SSL_ERROR_SSL)||(code&&ERR_GET_REASON(code)==SSL_R_UNEXPECTED_EOF_WHILE_READING)){ERR_clear_error();return 0;}
        // Anything else keeps OpenSSL's reason, e.g. a fatal alert from a client that rejected our certificate ("tlsv1 alert unknown ca").
        char reason[256]{};if(code)ERR_error_string_n(code,reason,sizeof(reason));ERR_clear_error();
        throw std::runtime_error(code?std::string("TLS read failed: ")+reason:e==SSL_ERROR_SYSCALL?"TLS read failed: "+lastSocketError():"TLS read failed (SSL_get_error "+std::to_string(e)+")");}
    void write(const char* data,size_t n){while(n){int r=ssl?SSL_write(ssl,data,int(std::min(n,size_t(16384)))):int(send(socket,data,int(std::min(n,size_t(16384))),0));if(r<=0)throw std::runtime_error("Write failed or timed out");data+=r;n-=size_t(r);}}
    void write(const std::string& s){write(s.data(),s.size());}
    bool line(std::string& out){while(true){auto p=buffer.find("\r\n");if(p!=std::string::npos){out=buffer.substr(0,p);buffer.erase(0,p+2);return true;}if(buffer.size()>65536)throw std::runtime_error("HTTP header exceeds 64 KiB");char b[16384];int n=read(b,sizeof(b));if(!n){if(!buffer.empty())throw std::runtime_error("HTTP header truncated");return false;}buffer.append(b,size_t(n));}}
    std::string take(size_t n){while(buffer.size()<n){char b[16384];int r=read(b,int(std::min(sizeof(b),n-buffer.size())));if(!r)throw std::runtime_error("Body ended before declared length");buffer.append(b,size_t(r));}auto s=buffer.substr(0,n);buffer.erase(0,n);return s;}
};
struct Tls {
    explicit Tls(std::string directory);~Tls();
    void initialize();
    SSL_CTX* leaf(const std::string& host);
    SSL_CTX* client=nullptr;
    std::string directory;
    json info() const;
    void trust(bool install);
private:
    X509* ca=nullptr;EVP_PKEY* caKey=nullptr;EVP_PKEY* leafKey=nullptr;
    std::mutex mutex;std::map<std::string,SSL_CTX*> leaves;
};
class Proxy {
public:
    Proxy(Store&,Tls&);~Proxy();
    void start(uint16_t port,bool mitm=true);void stop();json status() const;
private:
    struct Impl;std::unique_ptr<Impl> impl_;
};
// How an h2 connection ended when the client never opened a stream (e.g. it rejected our certificate).
struct H2End{bool noStreams=false;std::string clientError;};
H2End http2(Store&,Channel&,Channel&,const std::string& host,uint16_t port,const std::string& connection,const json& keys,const json& process,std::atomic<bool>& running);
}
