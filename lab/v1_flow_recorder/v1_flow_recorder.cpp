/*
============================================================
 v1_flow_recorder  —  "중계"에서 "기록"으로
============================================================
 목적: local-proxy-lab 의 proxy_v2(M2) 는 HTTP 를 파싱해서 '전달'까지 했다.
       WireScope 의 첫 단계는 거기서 한 발 더: 지나가는 요청 하나하나를
       "Flow" 라는 기록 단위로 남기는 것. (mitmproxy 의 flow 개념)

 [v1 단계 1]
   accept -> 요청 헤드 파싱 -> upstream connect -> 헤드+body 전달
          -> 응답 헤드 파싱 -> body 전달 -> (keep-alive 면) 다음 요청

 [v1 단계 2]
   + chunked (Transfer-Encoding) 전달, trailer 까지
   + 요청/응답 하나를 Flow 로 묶어서 flows.jsonl 에 한 줄씩 기록
       {id, method, host, port, path, status, 헤더(순서 그대로), body(base64),
        captured/total, timeline(ms), 연결 endpoint}

 ★ 기록할 때 지킨 원칙 (WireScope 본체까지 그대로 이어짐):
   1) body 는 방향별 1 MiB 까지만 '보관'하고, 전체 크기(total)는 끝까지 '센다'.
      -> 화면에 "1 MiB 중 1 MiB 보관 / 전체 1.5 MiB" 처럼 사실대로 보여줄 수 있게.
   2) chunked body 는 청크 껍데기(크기줄, CRLF)를 벗긴 '내용'만 기록한다.
      -> 그래서 기록된 바이트 수 != 실제 소켓으로 오간 바이트 수. 노트에 적어둠.
   3) "이건 파일 업로드다" 같은 판단은 기록에 넣지 않는다. 헤더/바이트/시간만.

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

#include "json.hpp"   // nlohmann/json (third_party). JSON 직렬화는 직접 안 짜고 라이브러리로.

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using json = nlohmann::json;

static const uint16_t LISTEN_PORT = 18081;
static const size_t BODY_LIMIT = 1024 * 1024;   // 방향별 보관 한도 (WireScope 와 같은 값)


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
// base64: 바이너리 body 를 JSON 문자열에 넣으려면 텍스트로 바꿔야 한다.
//   3바이트(24bit) -> 6bit 씩 4글자. 모자라면 '=' 로 채움.
//   (Go 라면 base64.StdEncoding.EncodeToString(b) 한 줄)
// ------------------------------------------------------------
static std::string base64(const std::string& in) {
    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        uint32_t v = (uint8_t(in[i]) << 16) | (uint8_t(in[i + 1]) << 8) | uint8_t(in[i + 2]);
        out += T[v >> 18]; out += T[(v >> 12) & 63]; out += T[(v >> 6) & 63]; out += T[v & 63];
    }
    if (i + 1 == in.size()) {
        uint32_t v = uint8_t(in[i]) << 16;
        out += T[v >> 18]; out += T[(v >> 12) & 63]; out += "==";
    } else if (i + 2 == in.size()) {
        uint32_t v = (uint8_t(in[i]) << 16) | (uint8_t(in[i + 1]) << 8);
        out += T[v >> 18]; out += T[(v >> 12) & 63]; out += T[(v >> 6) & 63]; out += '=';
    }
    return out;
}


// ------------------------------------------------------------
// Captured: body 를 '보관(앞 1 MiB)' 과 '세기(전체)' 로 나눠서 받는 그릇
// ------------------------------------------------------------
struct Captured {
    std::string bytes;      // 보관한 앞부분
    uint64_t total = 0;     // 실제로 지나간 전체 길이
    void add(const std::string& data) {
        total += data.size();
        if (bytes.size() < BODY_LIMIT) bytes.append(data, 0, std::min(data.size(), BODY_LIMIT - bytes.size()));
    }
    json toJson() const {
        return {{"base64", base64(bytes)}, {"captured", bytes.size()}, {"total", total}, {"truncated", total > bytes.size()}};
    }
};


// ------------------------------------------------------------
// Flow: 요청 하나 + 그 응답 하나 = 기록 단위
//   timeline 은 "언제 무엇이 일어났나" — 시작 기준 ms.
//   endpoints 는 [클라이언트<->프록시, 프록시<->서버] 소켓 주소.
//     -> v4/v5 에서 패킷 캡처와 맞춰볼 때 이 주소쌍이 연결 key 가 된다.
// ------------------------------------------------------------
struct Flow {
    uint64_t id = 0;
    int64_t started = 0;
    std::string method, host, path, error;
    uint16_t port = 0;
    int status = 0;
    Headers requestHeaders, responseHeaders, responseTrailers;
    Captured request, response;
    json timeline = json::array();
    json endpoints = json::array();

    void mark(const char* event) { timeline.push_back({{"t", nowMs() - started}, {"event", event}}); }
    json toJson() const {
        return {{"id", id}, {"time", started}, {"method", method}, {"host", host}, {"port", port}, {"path", path},
                {"status", status}, {"error", error}, {"requestHeaders", requestHeaders}, {"responseHeaders", responseHeaders},
                {"responseTrailers", responseTrailers}, {"request", request.toJson()}, {"response", response.toJson()},
                {"timeline", timeline}, {"endpoints", endpoints}};
    }
};

static std::atomic<uint64_t> g_nextId{1};
static std::mutex g_fileMutex;          // 여러 연결 스레드가 같은 파일에 쓰니까 한 줄씩 잠그고 쓴다
static std::string g_outPath = "flows.jsonl";

static void saveFlow(const Flow& f) {
    std::lock_guard<std::mutex> lock(g_fileMutex);
    std::ofstream out(g_outPath, std::ios::app | std::ios::binary);
    out << f.toJson().dump(-1, ' ', false, json::error_handler_t::replace) << "\n";   // JSON Lines: 한 줄 = Flow 하나
}


// ------------------------------------------------------------
// body 전달 (Content-Length / chunked / 연결 종료까지)
//   from 에서 정확히 n 바이트 읽어서 to 로 보낸다.
//   한 번에 다 읽지 않고 16KB 씩: 큰 파일 업로드도 메모리에 통째로 안 올림.
// ------------------------------------------------------------
static bool forwardExact(Reader& from, sock_t to, uint64_t n, Captured& cap) {
    while (n > 0) {
        std::string chunk;
        size_t want = size_t(std::min<uint64_t>(n, 16384));
        if (!from.exact(want, chunk)) return false;
        if (!lab::sendAll(to, chunk)) return false;
        cap.add(chunk);
        n -= chunk.size();
    }
    return true;
}

// chunked 형식:
//   1a\r\n            <- 16진수 청크 크기 (뒤에 ;확장 붙을 수 있음)
//   ...26바이트...\r\n
//   0\r\n              <- 크기 0 = 마지막 청크
//   X-Checksum: abc\r\n  <- (선택) trailer 헤더
//   \r\n
// 전달은 받은 줄을 그대로(껍데기 포함), 기록은 내용만.
static bool forwardChunked(Reader& from, sock_t to, Captured& cap, Headers* trailers) {
    for (;;) {
        std::string sizeLine;
        if (!from.line(sizeLine)) return false;
        lab::sendAll(to, sizeLine + "\r\n");
        uint64_t n = std::stoull(sizeLine.substr(0, sizeLine.find(';')), nullptr, 16);
        if (n == 0) {
            for (;;) {                                          // trailer 영역: 빈 줄까지
                std::string line;
                if (!from.line(line)) return false;
                lab::sendAll(to, line + "\r\n");
                if (line.empty()) return true;
                size_t c = line.find(':');
                if (trailers && c != std::string::npos) trailers->emplace_back(line.substr(0, c), trim(line.substr(c + 1)));
            }
        }
        if (!forwardExact(from, to, n, cap)) return false;
        std::string crlf;
        if (!from.exact(2, crlf) || crlf != "\r\n") return false;   // 청크 데이터 뒤엔 반드시 CRLF
        lab::sendAll(to, crlf);
    }
}

// 응답 body 길이를 모를 때 (Content-Length 없음): 서버가 연결을 끊을 때까지가 body
static void forwardUntilClose(Reader& from, sock_t to, Captured& cap) {
    if (!from.buf.empty()) {
        lab::sendAll(to, from.buf);
        cap.add(from.buf);
        from.buf.clear();
    }
    while (from.fill()) {
        lab::sendAll(to, from.buf);
        cap.add(from.buf);
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
        Flow flow;
        flow.id = g_nextId++;
        flow.started = nowMs();
        flow.requestHeaders = req.headers;
        flow.mark("request.headers");

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

        flow.method = method;
        flow.host = host;
        flow.port = port;
        flow.path = path;

        // 3. upstream 연결 (같은 host:port 면 재사용)
        if (up == BAD_SOCK || host != upHost || port != upPort) {
            lab::closeSock(up);
            up = lab::connectTo(host, port);
            if (up == BAD_SOCK) {
                lab::sendAll(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                flow.error = "upstream connect failed";
                flow.mark("connection.error");
                saveFlow(flow);                        // 실패도 기록 대상
                printf("[v1] #%llu connect 실패 %s:%u\n", (unsigned long long)flow.id, host.c_str(), port);
                break;
            }
            lab::setTimeout(up, 30);
            ur = Reader{up, {}};
            upHost = host;
            upPort = port;
        }

        flow.endpoints = {lab::endpointOf(client, true) + " | " + lab::endpointOf(client, false),
                          lab::endpointOf(up, false) + " | " + lab::endpointOf(up, true)};

        // 4. 요청 전달: 요청줄은 origin-form 으로, 프록시 전용 헤더는 제거
        Head out = req;
        out.startLine = method + " " + path + " HTTP/1.1";
        headerErase(out.headers, "Proxy-Connection");
        lab::sendAll(up, serialize(out));
        std::string cl = headerGet(req.headers, "Content-Length");
        bool ok = true;
        if (lower(headerGet(req.headers, "Transfer-Encoding")) == "chunked") ok = forwardChunked(cr, up, flow.request, nullptr);
        else if (!cl.empty()) ok = forwardExact(cr, up, std::stoull(cl), flow.request);
        flow.mark("request.end");

        // 5. 응답 헤드 받아서 그대로 전달
        Head res;
        if (!ok || !readHead(ur, res)) {
            flow.error = "request relay or response head failed";
            saveFlow(flow);
            break;
        }
        flow.mark("response.headers");
        flow.responseHeaders = res.headers;
        lab::sendAll(client, serialize(res));
        flow.status = std::atoi(res.startLine.c_str() + res.startLine.find(' ') + 1);

        // 6. 응답 body: 어떤 방식으로 끝나는지 헤더가 알려준다
        bool closeAfter = false;
        std::string rcl = headerGet(res.headers, "Content-Length");
        if (method == "HEAD" || flow.status == 204 || flow.status == 304) {
            // body 없음 (규칙상)
        } else if (lower(headerGet(res.headers, "Transfer-Encoding")) == "chunked") {
            ok = forwardChunked(ur, client, flow.response, &flow.responseTrailers);
        } else if (!rcl.empty()) {
            ok = forwardExact(ur, client, std::stoull(rcl), flow.response);
        } else {
            forwardUntilClose(ur, client, flow.response);   // 길이 정보 없음 = 서버가 끊을 때까지
            closeAfter = true;
        }
        if (!ok) flow.error = "response body ended early";
        flow.mark("response.end");
        saveFlow(flow);

        printf("[v1] #%llu %s %s:%u%s -> %d   req %llu B  res %llu B%s  %lld ms\n", (unsigned long long)flow.id, method.c_str(), host.c_str(), port,
               path.c_str(), flow.status, (unsigned long long)flow.request.total, (unsigned long long)flow.response.total,
               flow.response.total > flow.response.bytes.size() ? " (1 MiB 까지만 보관)" : "", (long long)(nowMs() - flow.started));
        if (!ok || closeAfter || lower(headerGet(req.headers, "Connection")) == "close") break;
    }
    lab::closeSock(up);
    lab::closeSock(client);
}


int main(int argc, char** argv) {
    lab::lineBufferedStdout();             // 파일/파이프로 보낼 때도 줄 단위로 바로 출력 (Windows 함정은 lab_net.hpp)
    if (argc > 1) g_outPath = argv[1];     // 기록 파일 경로 (기본 ./flows.jsonl)
    lab::netInit();
    sock_t listener = lab::listenLocal(LISTEN_PORT);
    if (listener == BAD_SOCK) {
        printf("listen 실패 (포트 %u 사용 중?)\n", LISTEN_PORT);
        return 1;
    }
    printf("[v1] 127.0.0.1:%u 에서 대기, 기록 -> %s\n     예) curl -x http://127.0.0.1:%u http://example.com/\n", LISTEN_PORT, g_outPath.c_str(), LISTEN_PORT);
    for (;;) {
        sock_t c = accept(listener, nullptr, nullptr);
        if (c == BAD_SOCK) continue;
        std::thread(handleClient, c).detach();       // 연결 하나 = 스레드 하나 (단순, 대신 수천 연결엔 부적합)
    }
}
