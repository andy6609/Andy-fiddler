/*
============================================================
 lab_net.hpp  —  lab 버전들이 같이 쓰는 소켓 헬퍼
============================================================
 왜 이 파일이 있나:
   local-proxy-lab 의 proxy_v1~v4 는 WinSock 만 썼다 (Windows 전용).
   WireScope 도 목표 OS 는 Windows 지만, 지금 개발/검증 호스트는 macOS 라서
   "윈도우 WinSock" 과 "맥/리눅스 BSD socket" 의 차이를 여기 한 군데서만 흡수한다.
   -> 각 lab 버전 코드는 프록시/패킷 로직에만 집중할 수 있게.

 차이 요약 (외워둘 만한 것만):
   | 항목             | Windows (WinSock)        | macOS/Linux (POSIX)      |
   |------------------|--------------------------|--------------------------|
   | 소켓 타입        | SOCKET (unsigned 포인터급) | int (파일 디스크립터)     |
   | 실패 값          | INVALID_SOCKET            | -1                       |
   | 닫기             | closesocket()             | close()                  |
   | 시작/정리        | WSAStartup / WSACleanup   | 필요 없음                 |
   | 끊긴 소켓에 send | 에러 코드 반환             | SIGPIPE 로 프로세스 죽음! -> 무시 설정 필요 |
   | 에러 번호        | WSAGetLastError()         | errno                    |
============================================================
*/
#pragma once

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <WinSock2.h>
  #include <WS2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  using sock_t = SOCKET;
  static const sock_t BAD_SOCK = INVALID_SOCKET;
#else
  #include <sys/socket.h>
  #include <sys/select.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <csignal>
  using sock_t = int;
  static const sock_t BAD_SOCK = -1;
#endif

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace lab {

// stdout 을 줄 단위로 바로 내보낸다 (파이프로 읽는 테스트나 다른 프로그램이 한 줄을 기다리며 멈추지 않게).
// 함정 (Windows 에서 실제로 걸림): MSVC CRT 에는 줄 버퍼링이 없다 (_IOLBF 가 _IOFBF 와 같다).
//   게다가 setvbuf(stdout, nullptr, _IOLBF, 0) 처럼 크기 0 을 주면 "invalid parameter" 로 프로세스가 그 자리에서 종료된다.
//   -> Windows 는 버퍼링을 아예 끈다(_IONBF). 콘솔 코드 페이지도 UTF-8 로 (한국어 출력이 안 깨지게).
inline void lineBufferedStdout() {
#ifdef _WIN32
    setvbuf(stdout, nullptr, _IONBF, 0);
    SetConsoleOutputCP(CP_UTF8);
#else
    setvbuf(stdout, nullptr, _IOLBF, 0);
#endif
}

// 프로그램 시작할 때 한 번. (TCP_toy 의 WSAStartup 자리)
inline void netInit() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    // 상대가 끊은 소켓에 send 하면 POSIX 는 SIGPIPE 시그널로 프로세스를 통째로 죽인다.
    // 프록시는 "한 연결이 죽어도 전체는 살아야" 하므로 무시하고 send 의 -1 반환으로 처리.
    std::signal(SIGPIPE, SIG_IGN);
#endif
}

inline void closeSock(sock_t s) {
    if (s == BAD_SOCK) return;
#ifdef _WIN32
    closesocket(s);
#else
    ::close(s);
#endif
}

// 반대 방향에 "나 더 보낼 거 없음(FIN)" 알리기. 양방향 릴레이 종료에 씀.
inline void shutdownSend(sock_t s) {
#ifdef _WIN32
    shutdown(s, SD_SEND);
#else
    shutdown(s, SHUT_WR);
#endif
}

// recv 가 영원히 안 끝나는 걸 막는 타임아웃 (느린/죽은 상대 대비)
inline void setTimeout(sock_t s, int seconds) {
#ifdef _WIN32
    DWORD t = DWORD(seconds * 1000);
#else
    timeval t{seconds, 0};
#endif
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&t), sizeof(t));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&t), sizeof(t));
}

// send 는 "요청한 만큼 다 보냈다"를 보장하지 않는다 (부분 전송). 다 보낼 때까지 반복.
inline bool sendAll(sock_t s, const char* data, size_t n) {
    while (n > 0) {
        int sent = int(send(s, data, int(n), 0));
        if (sent <= 0) return false;
        data += sent;
        n -= size_t(sent);
    }
    return true;
}
inline bool sendAll(sock_t s, const std::string& data) { return sendAll(s, data.data(), data.size()); }

// 127.0.0.1 에만 listen. (0.0.0.0 으로 열면 같은 네트워크의 남이 내 프록시를 쓸 수 있다)
inline sock_t listenLocal(uint16_t port) {
    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == BAD_SOCK) return BAD_SOCK;
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);                       // h(ost) to n(etwork) s(hort): 빅엔디안으로
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);     // 127.0.0.1
    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || listen(s, 64) != 0) {
        closeSock(s);
        return BAD_SOCK;
    }
    return s;
}

// 도메인 -> IP (getaddrinfo) -> 후보를 하나씩 connect.
// localhost 처럼 IPv6(::1) 와 IPv4(127.0.0.1) 둘 다 나오면 되는 쪽으로 붙는다.
inline sock_t connectTo(const std::string& host, uint16_t port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* list = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &list) != 0) return BAD_SOCK;
    sock_t s = BAD_SOCK;
    for (addrinfo* a = list; a; a = a->ai_next) {
        s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (s == BAD_SOCK) continue;
        if (connect(s, a->ai_addr, int(a->ai_addrlen)) == 0) break;
        closeSock(s);
        s = BAD_SOCK;
    }
    freeaddrinfo(list);
    return s;
}

// "IP:포트" 문자열 (getpeername/getsockname). peer=true 면 상대, false 면 내 쪽.
// 이 문자열이 나중에(v4~) 패킷의 연결 key 와 맞춰보는 단서가 된다.
inline std::string endpointOf(sock_t s, bool peer) {
    sockaddr_storage a{};
    socklen_t n = sizeof(a);
    int r = peer ? getpeername(s, reinterpret_cast<sockaddr*>(&a), &n) : getsockname(s, reinterpret_cast<sockaddr*>(&a), &n);
    if (r != 0) return "";
    char host[NI_MAXHOST]{}, port[NI_MAXSERV]{};
    if (getnameinfo(reinterpret_cast<sockaddr*>(&a), n, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV) != 0) return "";
    std::string h = host;
    if (h.find(':') != std::string::npos) h = "[" + h + "]";
    return h + ":" + port;
}

}  // namespace lab
