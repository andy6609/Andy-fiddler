/*
============================================================
 v1_flow_recorder  —  "중계"에서 "기록"으로
============================================================
 목적: local-proxy-lab 의 proxy_v2(M2) 는 HTTP 를 파싱해서 '전달'까지 했다.
       WireScope 의 첫 단계는 거기서 한 발 더: 지나가는 요청 하나하나를
       "Flow" 라는 기록 단위로 남기는 것. (mitmproxy 의 flow 개념)

 [v1 단계 1 — 이 커밋]
   accept -> 요청 헤드 파싱 -> upstream connect -> 헤드+body 전달
          -> 응답 헤드 파싱 -> body 전달 -> (keep-alive 면) 다음 요청
   body 길이는 Content-Length 만 지원. (chunked 는 다음 단계)

 흐름 그림:
     curl  --(GET http://host/path)-->  [v1 :18081]  --(GET /path)-->  host
           <--------- 응답 그대로 ----------          <---- 응답 -----

 왜 "absolute-form" 이 오나:
   프록시로 보낼 때 클라이언트는 요청줄에 전체 URL 을 쓴다.
     GET http://example.com:8080/a?b=1 HTTP/1.1     <- 프록시가 받는 것 (absolute-form)
     GET /a?b=1 HTTP/1.1                            <- 서버로 보내는 것 (origin-form)
   그래서 프록시가 여기서 host/port 를 떼고 origin-form 으로 바꿔 보낸다.
============================================================
*/

#include "lab_net.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <utility>
#include <vector>

static const uint16_t LISTEN_PORT = 18081;


// ------------------------------------------------------------
// Reader: 소켓 위의 버퍼드 리더 (proxy_v2 의 SockReader 와 같은 개념)
//
// TCP 는 메시지 경계가 없는 '바이트 흐름' 이다.
//   - 헤더가 recv 여러 번에 나눠 오기도 하고
//   - 한 번의 recv 에 헤더 + body 일부가 같이 오기도 한다 (over-read)
// -> 읽은 건 buf 에 쌓아두고 "한 줄" / "정확히 N 바이트" 단위로 꺼내 쓴다.
//    over-read 된 body 바이트를 버리면 안 된다! (buf 에 남아 있다가 exact() 가 가져감)
// ------------------------------------------------------------
struct Reader {
    sock_t s;
    std::string buf;

    bool fill() {
        char tmp[16384];
        int n = int(recv(s, tmp, sizeof(tmp), 0));
        if (n <= 0) return false;              // 0 = 상대가 FIN (정상 종료), -1 = 에러/타임아웃
        buf.append(tmp, size_t(n));
        return true;
    }
    bool line(std::string& out) {
        for (;;) {
            size_t p = buf.find("\r\n");
            if (p != std::string::npos) {
                out = buf.substr(0, p);
                buf.erase(0, p + 2);
                return true;
            }
            if (buf.size() > 64 * 1024) return false;   // 한 줄이 64KB 넘으면 정상 HTTP 아님
            if (!fill()) return false;
        }
    }
    bool exact(size_t n, std::string& out) {
        while (buf.size() < n)
            if (!fill()) return false;
        out = buf.substr(0, n);
        buf.erase(0, n);
        return true;
    }
};


// ------------------------------------------------------------
// HTTP 헤드 (start line + 헤더들)
// 헤더를 map 이 아니라 vector<pair> 로 두는 이유:
//   1) 같은 이름이 여러 번 나올 수 있다 (Set-Cookie 등)
//   2) 순서도 '관찰 대상' 이다 — 클라이언트마다 헤더 순서가 다르고, 그게 지문이 되기도 함
// ------------------------------------------------------------
using Headers = std::vector<std::pair<std::string, std::string>>;
struct Head {
    std::string startLine;   // "GET /a HTTP/1.1"  또는  "HTTP/1.1 200 OK"
    Headers headers;
};

static std::string lower(std::string s) {
    for (auto& c : s) c = char(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
static std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t");
    if (a == std::string::npos) return "";
    return s.substr(a, s.find_last_not_of(" \t") - a + 1);
}
// 헤더 이름은 대소문자 구분 안 함 (RFC 9110). "content-length" == "Content-Length"
static std::string headerGet(const Headers& h, const std::string& name) {
    for (auto& [k, v] : h)
        if (lower(k) == lower(name)) return v;
    return "";
}
static void headerErase(Headers& h, const std::string& name) {
    h.erase(std::remove_if(h.begin(), h.end(), [&](auto& kv) { return lower(kv.first) == lower(name); }), h.end());
}

// 빈 줄(\r\n\r\n)이 나올 때까지 = 헤드 끝
static bool readHead(Reader& r, Head& h) {
    h = {};
    if (!r.line(h.startLine) || h.startLine.empty()) return false;
    for (int i = 0; i < 200; i++) {                  // 헤더 200개 넘으면 비정상으로 봄
        std::string line;
        if (!r.line(line)) return false;
        if (line.empty()) return true;               // 빈 줄 = 헤드 끝, 이 뒤부터 body
        size_t colon = line.find(':');
        if (colon == std::string::npos || colon == 0) return false;
        h.headers.emplace_back(line.substr(0, colon), trim(line.substr(colon + 1)));
    }
    return false;
}
static std::string serialize(const Head& h) {
    std::string s = h.startLine + "\r\n";
    for (auto& [k, v] : h.headers) s += k + ": " + v + "\r\n";
    return s + "\r\n";
}

static int64_t nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}


// ------------------------------------------------------------
// body 전달 (단계 1: Content-Length 만)
//   from 에서 정확히 n 바이트 읽어서 to 로 보낸다.
//   한 번에 다 읽지 않고 16KB 씩: 큰 파일 업로드도 메모리에 통째로 안 올림.
// ------------------------------------------------------------
static bool forwardExact(Reader& from, sock_t to, uint64_t n, uint64_t& counted) {
    while (n > 0) {
        std::string chunk;
        size_t want = size_t(std::min<uint64_t>(n, 16384));
        if (!from.exact(want, chunk)) return false;
        if (!lab::sendAll(to, chunk)) return false;
        counted += chunk.size();
        n -= chunk.size();
    }
    return true;
}

// 응답 body 길이를 모를 때 (Content-Length 없음): 서버가 연결을 끊을 때까지가 body
static void forwardUntilClose(Reader& from, sock_t to, uint64_t& counted) {
    if (!from.buf.empty()) {
        lab::sendAll(to, from.buf);
        counted += from.buf.size();
        from.buf.clear();
    }
    while (from.fill()) {
        lab::sendAll(to, from.buf);
        counted += from.buf.size();
        from.buf.clear();
    }
}


// ------------------------------------------------------------
// 연결 하나 처리 (스레드 하나)
// ------------------------------------------------------------
static void handleClient(sock_t client) {
    lab::setTimeout(client, 30);
    Reader cr{client, {}};
    sock_t up = BAD_SOCK;
    std::string upHost;
    uint16_t upPort = 0;
    Reader ur{BAD_SOCK, {}};

    Head req;
    while (readHead(cr, req)) {                       // keep-alive: 한 연결에서 요청 여러 개
        int64_t started = nowMs();

        // 1. 요청줄 쪼개기: METHOD SP target SP version
        size_t s1 = req.startLine.find(' '), s2 = req.startLine.rfind(' ');
        if (s1 == std::string::npos || s2 == s1) break;
        std::string method = req.startLine.substr(0, s1);
        std::string target = req.startLine.substr(s1 + 1, s2 - s1 - 1);
        if (method == "CONNECT") {                    // HTTPS 터널은 v2 에서
            lab::sendAll(client, "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n");
            break;
        }

        // 2. absolute-form -> host, port, path
        if (target.rfind("http://", 0) != 0) break;   // 프록시 요청이 아니면 거절
        size_t slash = target.find('/', 7);
        std::string authority = target.substr(7, slash == std::string::npos ? std::string::npos : slash - 7);
        std::string path = slash == std::string::npos ? "/" : target.substr(slash);
        std::string host = authority;
        uint16_t port = 80;
        size_t colon = authority.rfind(':');
        if (colon != std::string::npos) {
            host = authority.substr(0, colon);
            port = uint16_t(std::stoi(authority.substr(colon + 1)));
        }

        // 3. upstream 연결 (같은 host:port 면 재사용)
        if (up == BAD_SOCK || host != upHost || port != upPort) {
            lab::closeSock(up);
            up = lab::connectTo(host, port);
            if (up == BAD_SOCK) {
                lab::sendAll(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                printf("[v1] connect 실패 %s:%u\n", host.c_str(), port);
                break;
            }
            lab::setTimeout(up, 30);
            ur = Reader{up, {}};
            upHost = host;
            upPort = port;
        }

        // 4. 요청 전달: 요청줄은 origin-form 으로, 프록시 전용 헤더는 제거
        Head out = req;
        out.startLine = method + " " + path + " HTTP/1.1";
        headerErase(out.headers, "Proxy-Connection");
        lab::sendAll(up, serialize(out));
        uint64_t reqBytes = 0;
        std::string cl = headerGet(req.headers, "Content-Length");
        if (!cl.empty() && !forwardExact(cr, up, std::stoull(cl), reqBytes)) break;

        // 5. 응답 헤드 받아서 그대로 전달
        Head res;
        if (!readHead(ur, res)) break;
        lab::sendAll(client, serialize(res));
        int status = std::atoi(res.startLine.c_str() + res.startLine.find(' ') + 1);

        // 6. 응답 body
        uint64_t resBytes = 0;
        bool closeAfter = false;
        std::string rcl = headerGet(res.headers, "Content-Length");
        if (method == "HEAD" || status == 204 || status == 304) {
            // body 없음
        } else if (!rcl.empty()) {
            if (!forwardExact(ur, client, std::stoull(rcl), resBytes)) break;
        } else {
            forwardUntilClose(ur, client, resBytes);
            closeAfter = true;
        }

        printf("[v1] %s %s:%u%s -> %d   req %llu B  res %llu B  %lld ms\n", method.c_str(), host.c_str(), port, path.c_str(), status,
               (unsigned long long)reqBytes, (unsigned long long)resBytes, (long long)(nowMs() - started));
        if (closeAfter || lower(headerGet(req.headers, "Connection")) == "close") break;
    }
    lab::closeSock(up);
    lab::closeSock(client);
}


int main() {
    setvbuf(stdout, nullptr, _IOLBF, 0);   // 파일/파이프로 보낼 때도 줄 단위로 바로 출력
    lab::netInit();
    sock_t listener = lab::listenLocal(LISTEN_PORT);
    if (listener == BAD_SOCK) {
        printf("listen 실패 (포트 %u 사용 중?)\n", LISTEN_PORT);
        return 1;
    }
    printf("[v1] 127.0.0.1:%u 에서 대기. 예) curl -x http://127.0.0.1:%u http://example.com/\n", LISTEN_PORT, LISTEN_PORT);
    for (;;) {
        sock_t c = accept(listener, nullptr, nullptr);
        if (c == BAD_SOCK) continue;
        std::thread(handleClient, c).detach();       // 연결 하나 = 스레드 하나 (단순, 대신 수천 연결엔 부적합)
    }
}
