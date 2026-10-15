#include "net.hpp"
#include "process.hpp"
#include <algorithm>
#include <charconv>
#include <thread>
#include <set>
#include <openssl/err.h>

namespace ws {
namespace {
struct Head {std::string line;Headers headers;};
bool readHead(Channel& c,Head& h){h={};if(!c.line(h.line))return false;if(h.line.empty()||h.line.size()>8192)throw std::runtime_error("Invalid HTTP start line");size_t total=h.line.size();for(int n=0;n<256;++n){std::string line;if(!c.line(line))throw std::runtime_error("HTTP headers truncated");total+=line.size()+2;if(total>65536)throw std::runtime_error("HTTP headers exceed 64 KiB");if(line.empty())return true;auto colon=line.find(':');if(colon==std::string::npos||colon==0||line[0]==' '||line[0]=='\t')throw std::runtime_error("Invalid HTTP header");auto key=line.substr(0,colon);if(key.find_first_of(" \t\r\n")!=std::string::npos)throw std::runtime_error("Invalid header name");h.headers.emplace_back(key,trim(line.substr(colon+1)));}throw std::runtime_error("Too many HTTP headers");}
std::string serialize(const Head& h){std::string s=h.line+"\r\n";for(auto& [k,v]:h.headers)s+=k+": "+v+"\r\n";return s+"\r\n";}
void eraseHeader(Headers& h,const std::string& key){h.erase(std::remove_if(h.begin(),h.end(),[&](auto& x){return lower(x.first)==key;}),h.end());}
uint64_t number(const std::string& s,int base=10){if(s.empty())throw std::runtime_error("Missing HTTP length");uint64_t n=0;auto [end,ec]=std::from_chars(s.data(),s.data()+s.size(),n,base);if(ec!=std::errc()||end!=s.data()+s.size()||n>(1ULL<<40))throw std::runtime_error("Invalid HTTP length");return n;}
struct Framing{enum Mode{None,Length,Chunked,Close}mode=None;uint64_t length=0;};
Framing framing(const Headers& h,bool response,bool noBody){std::string cl,te;bool has=false;for(auto& [k,v]:h){if(lower(k)=="content-length"){if(has&&cl!=trim(v))throw std::runtime_error("Conflicting Content-Length");cl=trim(v);has=true;}if(lower(k)=="transfer-encoding"){if(!te.empty())te+=",";te+=lower(trim(v));}}
    if(has&&!te.empty())throw std::runtime_error("Ambiguous HTTP framing: TE + Content-Length");if(noBody)return {};if(!te.empty()){if(te!="chunked")throw std::runtime_error("Unsupported Transfer-Encoding");return {Framing::Chunked,0};}if(has)return {Framing::Length,number(cl)};return {response?Framing::Close:Framing::None,0};}
std::pair<std::string,uint16_t> authority(const std::string& text,uint16_t port){std::string host=text;if(host.empty()||host.find_first_of(" /\\\r\n\t@,\0",0,9)!=std::string::npos)throw std::runtime_error("Invalid target authority");if(host.front()=='['){auto e=host.find(']');if(e==std::string::npos)throw std::runtime_error("Invalid IPv6 authority");if(e+1<host.size()){if(host[e+1]!=':')throw std::runtime_error("Invalid port");auto n=number(host.substr(e+2));if(n==0||n>65535)throw std::runtime_error("Invalid port");port=uint16_t(n);}host=host.substr(1,e-1);}else{auto p=host.rfind(':');if(p!=std::string::npos){auto n=number(host.substr(p+1));if(n==0||n>65535)throw std::runtime_error("Invalid port");port=uint16_t(n);host.resize(p);}}if(host.empty()||host.size()>253)throw std::runtime_error("Invalid host");for(unsigned char c:host)if(!std::isalnum(c)&&c!='.'&&c!='-'&&c!=':'&&c!='_')throw std::runtime_error("Invalid host character");return {host,port};}
void relayBody(Channel& from,Channel& to,const Framing& f,Store& store,uint64_t id,bool request,std::atomic<bool>& running){
    auto append=[&](const std::string& data){store.edit(id,[&](Flow& x){(request?x.request:x.response).append(data.data(),data.size());x.meta["state"]="streaming";});};
    auto exact=[&](uint64_t n){while(n){if(!running)throw std::runtime_error("Capture stopped");auto b=from.take(size_t(std::min(n,uint64_t(16384))));to.write(b);append(b);n-=b.size();}};
    if(f.mode==Framing::Length)exact(f.length);
    else if(f.mode==Framing::Chunked){for(;;){std::string line;if(!from.line(line))throw std::runtime_error("Chunk size missing");auto semi=line.find(';');auto n=number(trim(line.substr(0,semi)),16);to.write(line+"\r\n");if(!n){size_t total=0;Headers trailers;for(;;){if(!from.line(line))throw std::runtime_error("Trailers truncated");total+=line.size()+2;if(total>65536)throw std::runtime_error("Trailers too large");to.write(line+"\r\n");if(line.empty())break;auto c=line.find(':');if(c!=std::string::npos&&c)trailers.emplace_back(line.substr(0,c),trim(line.substr(c+1)));}if(!trailers.empty())store.edit(id,[&](Flow& x){x.meta[request?"requestTrailers":"responseTrailers"]=trailers;});break;}exact(n);if(from.take(2)!="\r\n")throw std::runtime_error("Invalid chunk terminator");to.write("\r\n");}}
    else if(f.mode==Framing::Close){if(!from.buffer.empty()){to.write(from.buffer);append(from.buffer);from.buffer.clear();}while(running){char b[16384];int n=from.read(b,sizeof(b));if(!n)break;to.write(b,size_t(n));append(std::string(b,size_t(n)));}if(!running)throw std::runtime_error("Capture stopped");}
}
std::string tlsError(){unsigned long e=ERR_get_error();char b[256]{};ERR_error_string_n(e,b,sizeof(b));return b;}
}
struct Proxy::Impl {
    Store& store;Tls& tls;std::atomic<bool> running{false};sock_t listener=bad_socket;std::thread accepter;
    mutable std::mutex mutex;std::map<sock_t,sock_t> sockets;std::string error;uint16_t listenPort=18080;bool mitm=true;
    struct Worker{std::thread thread;std::shared_ptr<std::atomic<bool>> done;};std::vector<Worker> workers;
    Impl(Store& s,Tls& t):store(s),tls(t){}
    void connect(Channel& up,sock_t client,const std::string& host,uint16_t port){
        {std::lock_guard lock(mutex);sockets[client]=bad_socket;up.reset();}
        addrinfo hints{},*result=nullptr;hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;
        if(getaddrinfo(host.c_str(),std::to_string(port).c_str(),&hints,&result)!=0)throw std::runtime_error("DNS lookup failed: "+host);
        for(auto* a=result;a&&running;a=a->ai_next){sock_t s=socket(a->ai_family,a->ai_socktype,a->ai_protocol);if(s==bad_socket)continue;{std::lock_guard lock(mutex);sockets[client]=s;}nonblocking(s,true);int resultCode=::connect(s,a->ai_addr,int(a->ai_addrlen));bool ok=resultCode==0;auto end=nowMs()+10000;while(!ok&&running&&nowMs()<end){
            // Windows reports a failed non-blocking connect only in exceptfds (POSIX: writefds), so watch both.
            fd_set w,x;FD_ZERO(&w);FD_ZERO(&x);FD_SET(s,&w);FD_SET(s,&x);timeval tv{0,100000};if(select(int(s)+1,nullptr,&w,&x,&tv)>0){int e=0;
#ifdef _WIN32
int n=sizeof(e);
#else
socklen_t n=sizeof(e);
#endif
getsockopt(s,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&e),&n);ok=e==0;break;}}
            if(ok){nonblocking(s,false);socketTimeout(s,60);up.socket=s;break;}{std::lock_guard lock(mutex);sockets[client]=bad_socket;closeSocket(s);}
        }freeaddrinfo(result);if(up.socket==bad_socket)throw std::runtime_error("Upstream connection failed: "+host);
    }
    json keys(Channel& c,Channel& u){return json::array({connectionKey(socketAddress(c.socket,true),socketAddress(c.socket,false)),connectionKey(socketAddress(u.socket,true),socketAddress(u.socket,false))});}
    void tunnel(Channel& c,Channel& u,uint64_t id){
        auto pending=[&](Channel& a,Channel& b,bool request){if(a.buffer.empty())return;auto data=std::move(a.buffer);a.buffer.clear();b.write(data);store.edit(id,[&](Flow& f){(request?f.request:f.response).append(data.data(),data.size());});};pending(c,u,true);pending(u,c,false);
        while(running){fd_set r;FD_ZERO(&r);FD_SET(c.socket,&r);FD_SET(u.socket,&r);timeval tv{0,100000};int n=select(int(std::max(c.socket,u.socket))+1,&r,nullptr,nullptr,&tv);if(n<0)break;for(auto [from,to,request]:{std::tuple<Channel*,Channel*,bool>{&c,&u,true},{&u,&c,false}}){if(!FD_ISSET(from->socket,&r)&&!(from->ssl&&SSL_pending(from->ssl)))continue;char b[16384];int size=from->read(b,sizeof(b));if(!size)return;to->write(b,size_t(size));const bool upward=request;/* C++17: lambdas cannot capture structured bindings */store.edit(id,[&](Flow& f){(upward?f.request:f.response).append(b,size_t(size));});}}
    }
    void serve(sock_t socket){Channel client,up;client.socket=socket;socketTimeout(socket,60);uint64_t active=0;std::string conn="tcp-"+randomHex(8);int64_t started=nowMs();
        struct Cleanup{Impl* p;sock_t s;~Cleanup(){std::lock_guard lock(p->mutex);p->sockets.erase(s);}} cleanup{this,socket};
        // Who opened this connection: looked up before the first read, while the app's socket is surely still in the TCP table (Windows only; null elsewhere).
        const json process=processForConnection(socketAddress(socket,true),socketAddress(socket,false));auto attributed=[&](json meta){if(!process.is_null())meta["process"]=process;return meta;};
        try{Head head;if(!readHead(client,head))return;std::string tunnelHost;uint16_t tunnelPort=443;bool secure=false;
            if(startsWith(head.line,"CONNECT ")){
                auto space=head.line.find(' ',8);if(space==std::string::npos)throw std::runtime_error("Invalid CONNECT");auto [host,port]=authority(head.line.substr(8,space-8),443);tunnelHost=host;tunnelPort=port;
                active=store.createFlow(attributed({{"method","CONNECT"},{"host",host},{"port",port},{"path",endpoint(host,port)},{"protocol","Tunnel"},{"connection",conn}}),head.headers);
                connect(up,socket,host,port);store.edit(active,[&](Flow& f){f.meta["packetKeys"]=keys(client,up);});client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
                if(!mitm){store.edit(active,[](Flow& f){f.meta["status"]=200;f.meta["state"]="streaming";f.meta["encrypted"]=true;});tunnel(client,up,active);store.edit(active,[&](Flow& f){f.meta["state"]="complete";f.meta["duration"]=nowMs()-started;});return;}
                if(!client.buffer.empty())throw std::runtime_error("Pipelined TLS handshake is not supported");
                client.ssl=SSL_new(tls.leaf(host));SSL_set_fd(client.ssl,int(client.socket));if(SSL_accept(client.ssl)!=1)throw std::runtime_error("Client TLS: "+tlsError());
                const unsigned char* alpn=nullptr;unsigned alpnLen=0;SSL_get0_alpn_selected(client.ssl,&alpn,&alpnLen);bool h2=alpnLen==2&&std::string(reinterpret_cast<const char*>(alpn),2)=="h2";
                up.ssl=SSL_new(tls.client);SSL_set_fd(up.ssl,int(up.socket));SSL_set_tlsext_host_name(up.ssl,host.c_str());unsigned char ip[16];bool numeric=inet_pton(AF_INET,host.c_str(),ip)==1||inet_pton(AF_INET6,host.c_str(),ip)==1;
                if(numeric)X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(up.ssl),host.c_str());else SSL_set1_host(up.ssl,host.c_str());
                static const unsigned char h2alpn[]={2,'h','2'}, h1alpn[]={8,'h','t','t','p','/','1','.','1'};SSL_set_alpn_protos(up.ssl,h2?h2alpn:h1alpn,h2?sizeof(h2alpn):sizeof(h1alpn));if(SSL_connect(up.ssl)!=1)throw std::runtime_error("Upstream TLS verification: "+tlsError());const unsigned char* selected=nullptr;unsigned selectedLen=0;SSL_get0_alpn_selected(up.ssl,&selected,&selectedLen);if(h2&&(selectedLen!=2||std::string(reinterpret_cast<const char*>(selected),2)!="h2"))throw std::runtime_error("Upstream did not negotiate h2; no HTTP/2-to-HTTP/1 translation");
                store.edit(active,[&](Flow& f){f.meta["status"]=200;f.meta["state"]="complete";f.meta["duration"]=nowMs()-started;f.meta["tls"]=SSL_get_version(client.ssl);f.meta["cipher"]=SSL_get_cipher(client.ssl);f.meta["alpn"]=h2?"h2":"http/1.1";f.timeline.push_back({{"time",nowMs()},{"event","tls.established"}});});active=0;
                if(h2){http2(store,client,up,tunnelHost,tunnelPort,conn,keys(client,up),process,running);return;}secure=true;if(!readHead(client,head))return;
            }
            std::string connectedHost=secure?tunnelHost:"";uint16_t connectedPort=secure?tunnelPort:0;
            do{if(!running)break;started=nowMs();auto s1=head.line.find(' '),s2=head.line.find(' ',s1==std::string::npos?0:s1+1);if(s1==std::string::npos||s2==std::string::npos)throw std::runtime_error("Invalid request line");std::string method=head.line.substr(0,s1),path=head.line.substr(s1+1,s2-s1-1);if(head.line.substr(s2+1)!="HTTP/1.1"&&head.line.substr(s2+1)!="HTTP/1.0")throw std::runtime_error("Unsupported HTTP version");auto [host,port]=authority(header(head.headers,"host"),secure?443:80);
                if(startsWith(path,"http://")){if(secure)throw std::runtime_error("Absolute HTTP target inside TLS tunnel");auto end=path.find_first_of("/?",7);auto hp=authority(path.substr(7,end==std::string::npos?end:end-7),80);host=hp.first;port=hp.second;path=end==std::string::npos?"/":path.substr(end);if(path.front()=='?')path="/"+path;eraseHeader(head.headers,"host");head.headers.emplace_back("Host",endpoint(host,port));}
                if(path.empty()||(path[0]!='/'&&path!="*"))throw std::runtime_error("Invalid request target");if(secure&&(lower(host)!=lower(tunnelHost)||port!=tunnelPort))throw std::runtime_error("Host differs from CONNECT authority");
                active=store.createFlow(attributed({{"method",method},{"host",host},{"port",port},{"path",path},{"protocol",head.line.substr(s2+1)},{"connection",conn},{"tls",secure?SSL_get_version(client.ssl):""}}),head.headers);
                if(host!=connectedHost||port!=connectedPort||up.socket==bad_socket){connect(up,socket,host,port);connectedHost=host;connectedPort=port;}
                store.edit(active,[&](Flow& f){f.meta["packetKeys"]=keys(client,up);});auto requestFrame=framing(head.headers,false,false);
                if(lower(header(head.headers,"expect"))=="100-continue"){client.write("HTTP/1.1 100 Continue\r\n\r\n");eraseHeader(head.headers,"expect");}
                Head outgoing=head;outgoing.line=method+" "+path+" HTTP/1.1";eraseHeader(outgoing.headers,"proxy-authorization");eraseHeader(outgoing.headers,"proxy-connection");up.write(serialize(outgoing));relayBody(client,up,requestFrame,store,active,true,running);store.edit(active,[](Flow& f){f.timeline.push_back({{"time",nowMs()},{"event","request.end"}});});
                Head response;int status=0;for(;;){if(!readHead(up,response))throw std::runtime_error("Upstream closed before response");auto p=response.line.find(' ');if(p==std::string::npos)throw std::runtime_error("Invalid response status");auto value=response.line.substr(p+1,3);status=int(number(value));if(status<100||status>599)throw std::runtime_error("Invalid response status");if(status>=200||status==101)break;client.write(serialize(response));}
                auto rf=framing(response.headers,true,method=="HEAD"||status==204||status==304||status==101);store.edit(active,[&](Flow& f){f.responseHeaders=response.headers;f.meta["status"]=status;f.meta["state"]="streaming";f.timeline.push_back({{"time",nowMs()},{"event","response.headers"}});});client.write(serialize(response));
                if(status==101){store.edit(active,[](Flow& f){f.meta["protocol"]="WebSocket";});tunnel(client,up,active);}else relayBody(up,client,rf,store,active,false,running);
                store.edit(active,[&](Flow& f){f.meta["duration"]=nowMs()-started;f.meta["state"]=running?"complete":"interrupted";f.timeline.push_back({{"time",nowMs()},{"event","response.end"}});});active=0;
                if(status==101||rf.mode==Framing::Close||lower(header(head.headers,"connection"))=="close"||lower(header(response.headers,"connection"))=="close"||endsWith(head.line,"HTTP/1.0"))break;
            }while(readHead(client,head));
        }catch(const std::exception& e){if(!active)active=store.createFlow(attributed({{"method","—"},{"host",socketAddress(socket,true)},{"path",""},{"protocol","Connection"},{"connection",conn}}));store.edit(active,[&](Flow& f){f.meta["state"]="error";f.meta["error"]=e.what();f.meta["duration"]=nowMs()-started;f.timeline.push_back({{"time",nowMs()},{"event","connection.error"}});});}
    }
};
Proxy::Proxy(Store& s,Tls& t):impl_(std::make_unique<Impl>(s,t)){}
Proxy::~Proxy(){stop();}
void Proxy::start(uint16_t port,bool mitm){stop();auto& i=*impl_;if(!port)throw std::runtime_error("Proxy port must be 1–65535");i.tls.initialize();sock_t listener=socket(AF_INET,SOCK_STREAM,0);if(listener==bad_socket)throw std::runtime_error("Cannot create proxy socket");int opt=1;
#ifdef _WIN32
setsockopt(listener,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&opt),sizeof(opt));
#else
setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
#endif
sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);addr.sin_port=htons(port);if(bind(listener,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))!=0||listen(listener,64)!=0){closeSocket(listener);throw std::runtime_error("Proxy port is unavailable");}i.listener=listener;i.listenPort=port;i.mitm=mitm;i.running=true;{std::lock_guard lock(i.mutex);i.error.clear();}
    i.accepter=std::thread([&i]{while(i.running){fd_set r;FD_ZERO(&r);FD_SET(i.listener,&r);timeval tv{0,100000};if(select(int(i.listener)+1,&r,nullptr,nullptr,&tv)<=0)continue;auto s=accept(i.listener,nullptr,nullptr);if(s==bad_socket)continue;{std::lock_guard lock(i.mutex);if(i.sockets.size()>=64||!i.running){closeSocket(s);continue;}i.sockets[s]=bad_socket;}
        for(auto it=i.workers.begin();it!=i.workers.end();){if(it->done->load()){it->thread.join();it=i.workers.erase(it);}else ++it;}
        auto done=std::make_shared<std::atomic<bool>>(false);i.workers.push_back({std::thread([&i,s,done]{try{i.serve(s);}catch(...){std::lock_guard lock(i.mutex);i.error="Unhandled connection error";i.sockets.erase(s);}*done=true;}),done});}
    });
}
void Proxy::stop(){auto& i=*impl_;i.running=false;if(i.accepter.joinable())i.accepter.join();closeSocket(i.listener);i.listener=bad_socket;{std::lock_guard lock(i.mutex);for(auto& [c,u]:i.sockets){shutdownSocket(c);shutdownSocket(u);}}for(auto& w:i.workers)if(w.thread.joinable())w.thread.join();i.workers.clear();}
json Proxy::status()const{auto& i=*impl_;std::lock_guard lock(i.mutex);return {{"running",i.running.load()},{"port",i.listenPort},{"mitm",i.mitm},{"connections",i.sockets.size()},{"error",i.error}};}
}
