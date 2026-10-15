/*
============================================================
 v2_tls_recorder  —  HTTPS: 터널을 '통과'시킬 것인가, '끊고' 볼 것인가
============================================================
 목적: v1 은 평문 HTTP 만 봤다. 요즘 트래픽은 거의 다 HTTPS 라서
       클라이언트는 프록시에게 이렇게 말한다:
         CONNECT api.example.com:443 HTTP/1.1      "이 주소로 TCP 터널 좀 뚫어줘"
       프록시가 "200 Connection Established" 를 보내는 순간부터 그 연결 위로는
       TLS(암호화된 바이트)가 흐른다.

 [v2 단계 1 — passthrough (이 커밋)]
   CONNECT -> upstream TCP 연결 -> 200 -> 양방향 blind 릴레이 (select 로 두 소켓 감시)
   내용은 못 보지만, 그래도 '관찰할 수 있는 것'이 있다. 그걸 다 기록한다:
     - 방향별 바이트 수, 타이밍
     - 첫 바이트들 = TLS 레코드 헤더 (0x16 = Handshake, 0x17 = Application Data ...)
     - ClientHello 안의 SNI(server_name) — 암호화 '전'에 평문으로 지나가는 host 이름!
   => "암호화돼도 보이는 것 vs 안 보이는 것" 의 경계를 직접 확인하는 단계.

 local-proxy-lab 과의 연결:
   proxy_v3(M3) 의 CONNECT raw 터널과 같은 구조. 차이는 '기록'과 TLS 헤더 해석.
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

static const uint16_t LISTEN_PORT = 18082;
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
    json observed = json::object();     // 암호화 터널에서 '밖에서도 보이는 것' (TLS 레코드, SNI)

    void mark(const char* event) { timeline.push_back({{"t", nowMs() - started}, {"event", event}}); }
    json toJson() const {
        return {{"id", id}, {"time", started}, {"method", method}, {"host", host}, {"port", port}, {"path", path},
                {"status", status}, {"error", error}, {"requestHeaders", requestHeaders}, {"responseHeaders", responseHeaders},
                {"responseTrailers", responseTrailers}, {"request", request.toJson()}, {"response", response.toJson()},
                {"timeline", timeline}, {"endpoints", endpoints}, {"observed", observed}};
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
// TLS 레코드 헤더 읽기 — 암호화돼 있어도 '껍데기 5바이트'는 평문이다.
//
//   [content type 1B][version 2B][length 2B][ ...암호화된(또는 핸드셰이크) 데이터... ]
//     0x14 ChangeCipherSpec / 0x15 Alert / 0x16 Handshake / 0x17 ApplicationData
//
// 그리고 첫 Handshake 메시지(ClientHello)는 아직 암호화 전이라서
// 그 안의 SNI 확장(server_name) 에 접속하려는 host 이름이 평문으로 들어 있다.
//   -> 회사 방화벽이 HTTPS 를 안 풀고도 "어느 사이트인지" 아는 이유.
//   (TLS 1.3 + ECH 를 쓰면 이것도 가려진다. 아직은 드묾)
// ------------------------------------------------------------
static uint16_t be16(const std::string& s, size_t p) { return uint16_t((uint8_t(s[p]) << 8) | uint8_t(s[p + 1])); }

static std::string findSni(const std::string& rec) {
    // rec = TLS 레코드 하나. 5바이트 레코드 헤더 뒤가 Handshake 메시지.
    if (rec.size() < 9 || uint8_t(rec[0]) != 0x16 || uint8_t(rec[5]) != 0x01) return "";   // Handshake + ClientHello(1)
    size_t p = 5 + 4;                 // handshake 헤더(type 1 + length 3)
    p += 2 + 32;                      // client_version + random
    if (p >= rec.size()) return "";
    p += 1 + uint8_t(rec[p]);         // session_id
    if (p + 2 > rec.size()) return "";
    p += 2 + be16(rec, p);            // cipher_suites
    if (p >= rec.size()) return "";
    p += 1 + uint8_t(rec[p]);         // compression_methods
    if (p + 2 > rec.size()) return "";
    size_t end = std::min(rec.size(), p + 2 + be16(rec, p));
    p += 2;
    while (p + 4 <= end) {            // extensions: [type 2B][len 2B][data]
        uint16_t type = be16(rec, p), len = be16(rec, p + 2);
        p += 4;
        if (type == 0 && p + 5 <= end) {   // server_name: list len(2) + name type(1) + name len(2) + name
            uint16_t nameLen = be16(rec, p + 3);
            if (p + 5 + nameLen <= end) return rec.substr(p + 5, nameLen);
        }
        p += len;
    }
    return "";
}

static json describeTls(const std::string& bytes) {
    if (bytes.size() < 5) return nullptr;
    static const char* names[] = {"ChangeCipherSpec", "Alert", "Handshake", "ApplicationData"};
    uint8_t type = uint8_t(bytes[0]);
    json j = {{"firstRecordType", type}, {"firstRecordVersion", be16(bytes, 1)}, {"firstRecordLength", be16(bytes, 3)}};
    if (type >= 20 && type <= 23) j["firstRecordName"] = names[type - 20];
    std::string sni = findSni(bytes);
    if (!sni.empty()) j["sni"] = sni;
    return j;
}


// ------------------------------------------------------------
// tunnel: 두 소켓을 select 로 동시에 지켜보면서 온 쪽에서 반대쪽으로 넘김
//   proxy_v1 의 "스레드 2개 Relay" 대신 select 하나로 양방향 처리.
//   (select = "이 소켓들 중 읽을 게 생긴 놈 알려줘" — Go 의 select{} 랑 이름만 비슷하고
//    여기선 OS 가 소켓 상태를 알려주는 시스템콜)
// ------------------------------------------------------------
static void tunnel(Reader& cr, sock_t up, Flow& flow) {
    sock_t client = cr.s;
    // CONNECT 헤드를 읽을 때 같이 읽혀버린 바이트(=클라가 성급하게 보낸 ClientHello)가 있으면 먼저 보냄
    if (!cr.buf.empty()) {
        lab::sendAll(up, cr.buf);
        flow.request.add(cr.buf);
        cr.buf.clear();
    }
    char buf[16384];
    for (;;) {
        fd_set r;
        FD_ZERO(&r);
        FD_SET(client, &r);
        FD_SET(up, &r);
        timeval tv{30, 0};
        int n = select(int(std::max(client, up)) + 1, &r, nullptr, nullptr, &tv);
        if (n <= 0) break;                                   // 30초 동안 양쪽 다 조용하거나 에러
        if (FD_ISSET(client, &r)) {
            int k = int(recv(client, buf, sizeof(buf), 0));
            if (k <= 0) break;
            if (flow.request.total == 0) flow.mark("tunnel.client.first");
            lab::sendAll(up, buf, size_t(k));
            flow.request.add(std::string(buf, size_t(k)));
        }
        if (FD_ISSET(up, &r)) {
            int k = int(recv(up, buf, sizeof(buf), 0));
            if (k <= 0) break;
            if (flow.response.total == 0) flow.mark("tunnel.server.first");
            lab::sendAll(client, buf, size_t(k));
            flow.response.add(std::string(buf, size_t(k)));
        }
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
        if (method == "CONNECT") {
            // target = "host:443" (authority-form)
            size_t c = target.rfind(':');
            flow.method = method;
            flow.host = c == std::string::npos ? target : target.substr(0, c);
            flow.port = c == std::string::npos ? 443 : uint16_t(std::stoi(target.substr(c + 1)));
            flow.path = target;
            up = lab::connectTo(flow.host, flow.port);
            if (up == BAD_SOCK) {
                lab::sendAll(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                flow.error = "upstream connect failed";
                saveFlow(flow);
                break;
            }
            flow.endpoints = {lab::endpointOf(client, true) + " | " + lab::endpointOf(client, false),
                              lab::endpointOf(up, false) + " | " + lab::endpointOf(up, true)};
            lab::sendAll(client, "HTTP/1.1 200 Connection Established\r\n\r\n");
            flow.status = 200;
            flow.mark("tunnel.open");
            tunnel(cr, up, flow);                      // ★ 여기부터 암호 바이트. 내용은 못 봄
            flow.mark("tunnel.close");
            flow.observed = {{"client", describeTls(flow.request.bytes)}, {"server", describeTls(flow.response.bytes)}};
            saveFlow(flow);
            const json& hello = flow.observed["client"];
            std::string sni = hello.is_object() ? hello.value("sni", std::string("?")) : "?";
            printf("[v2] #%llu CONNECT %s  (sni=%s)  client->server %llu B  server->client %llu B\n", (unsigned long long)flow.id,
                   target.c_str(), sni.c_str(),
                   (unsigned long long)flow.request.total, (unsigned long long)flow.response.total);
            break;                                     // 터널 끝 = 연결 끝
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
                printf("[v2] #%llu connect 실패 %s:%u\n", (unsigned long long)flow.id, host.c_str(), port);
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

        printf("[v2] #%llu %s %s:%u%s -> %d   req %llu B  res %llu B%s  %lld ms\n", (unsigned long long)flow.id, method.c_str(), host.c_str(), port,
               path.c_str(), flow.status, (unsigned long long)flow.request.total, (unsigned long long)flow.response.total,
               flow.response.total > flow.response.bytes.size() ? " (1 MiB 까지만 보관)" : "", (long long)(nowMs() - flow.started));
        if (!ok || closeAfter || lower(headerGet(req.headers, "Connection")) == "close") break;
    }
    lab::closeSock(up);
    lab::closeSock(client);
}


int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IOLBF, 0);   // 파일/파이프로 보낼 때도 줄 단위로 바로 출력
    if (argc > 1) g_outPath = argv[1];     // 기록 파일 경로 (기본 ./flows.jsonl)
    lab::netInit();
    sock_t listener = lab::listenLocal(LISTEN_PORT);
    if (listener == BAD_SOCK) {
        printf("listen 실패 (포트 %u 사용 중?)\n", LISTEN_PORT);
        return 1;
    }
    printf("[v2] 127.0.0.1:%u 에서 대기, 기록 -> %s\n     예) curl -x http://127.0.0.1:%u http://example.com/\n", LISTEN_PORT, g_outPath.c_str(), LISTEN_PORT);
    for (;;) {
        sock_t c = accept(listener, nullptr, nullptr);
        if (c == BAD_SOCK) continue;
        std::thread(handleClient, c).detach();       // 연결 하나 = 스레드 하나 (단순, 대신 수천 연결엔 부적합)
    }
}
