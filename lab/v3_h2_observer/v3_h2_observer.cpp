/*
============================================================
 v3_h2_observer  —  HTTP/2 를 프레임 단위로 보기
============================================================
 목적: v2 는 ALPN 에서 http/1.1 만 골라서 h2 클라이언트도 1.1 로 끌어내렸다.
       그런데 브라우저, AI 앱, 대부분의 SDK 는 실제로 h2 를 쓴다.
       '실제 모습'을 보려면 h2 가 어떻게 생겼는지부터 알아야 한다.

 HTTP/1.1 vs HTTP/2 (한 연결 안에서):
   1.1 : 텍스트 줄. 요청 하나 끝나야 다음 요청 (keep-alive 여도 순서대로)
   h2  : 바이너리 '프레임'. 요청 여러 개가 stream ID 로 구분돼 섞여서(multiplexing) 흐른다.

   프레임 = [length 3B][type 1B][flags 1B][R 1bit + stream id 31bit][payload ...]
     type: 0 DATA / 1 HEADERS / 2 PRIORITY / 3 RST_STREAM / 4 SETTINGS / 5 PUSH_PROMISE
           6 PING / 7 GOAWAY / 8 WINDOW_UPDATE / 9 CONTINUATION
     stream id 0 = 연결 전체에 대한 제어 프레임 (SETTINGS, PING, GOAWAY ...)
     클라이언트가 여는 stream 은 홀수 (1, 3, 5 ...)

 [v3 단계 1]  프레임 헤더만 읽는 '투명한' 관찰자
   CONNECT -> 200 -> 양쪽 TLS 종단(ALPN h2) -> 복호화된 바이트를 '그대로' 반대쪽에 다시 암호화해서 보냄
                                           -> 보내면서 9바이트 프레임 헤더를 파싱해서 기록
   바이트를 하나도 안 바꾸니까 SETTINGS/흐름제어(WINDOW_UPDATE)는 클라와 서버가 직접 협상한다.
   우리는 옆에서 보기만 함.

   아직 못 보는 것: HEADERS 프레임 내용. h2 헤더는 HPACK 으로 압축돼 있다 -> 단계 2.

 [v3 단계 2]  HPACK 해제 -> stream 하나 = 요청/응답 하나로 복원
   HPACK 이 그냥 gzip 같은 압축이 아닌 이유:
     - 정적 테이블: ":method: GET" 같은 자주 쓰는 헤더 61개는 번호 1바이트로 보냄
     - 동적 테이블: 한 번 보낸 헤더는 연결 내내 기억해 두고 다음부터 번호로 보냄
         (그래서 user-agent, authorization 같은 긴 헤더가 두 번째 요청부터는 1~2바이트)
     - 허프만 코딩: 문자열 자체도 짧게
   => 동적 테이블 때문에 '방향별로, 순서대로, 빠짐없이' 모든 HEADERS 를 풀어야 한다.
      중간 하나라도 건너뛰면 이후 번호가 다 어긋난다. (stateful)
   여기선 nghttp2 라이브러리의 inflater(HPACK 해제기)만 빌려 쓴다. 방향마다 하나.

   그리고 stream 별로 모은다:
     C->S HEADERS (+CONTINUATION) -> 요청 헤더 (:method :path :authority :scheme ...)
     C->S DATA                    -> 요청 body
     S->C HEADERS                 -> 응답 헤더 (:status ...)
     S->C DATA                    -> 응답 body
     S->C HEADERS (두 번째)        -> trailer
     END_STREAM / RST_STREAM      -> 그 stream 끝 -> 한 줄 기록

 WireScope 본체(src/http2.cpp)와 다른 점:
   본체는 nghttp2 '세션' 두 개를 세워서 프레임을 다시 만들어 보낸다(bridge).
   v3 는 바이트를 안 바꾸고 옆에서 풀어보기만 한다(observer). 노트 v3-notes.md 참고.
============================================================
*/

#include "lab_net.hpp"

#include "json.hpp"

// MSVC 에는 ssize_t 가 없다. 이 매크로를 켜면 nghttp2.h 가 ssize_t 를 쓰는 옛 API 선언을 빼서 Windows 에서도 컴파일된다.
// (v3 는 처음부터 nghttp2_ssize 를 쓰는 hd_inflate_hd3 만 쓰므로 잃는 것이 없다)
#define NGHTTP2_NO_SSIZE_T
#include <nghttp2/nghttp2.h>       // HPACK inflater 만 사용
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using json = nlohmann::json;

static const uint16_t LISTEN_PORT = 18083;
static const size_t BODY_LIMIT = 1024 * 1024;
static std::string g_outPath = "flows.jsonl";
static std::mutex g_fileMutex;
static std::atomic<uint64_t> g_nextId{1};

static int64_t nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}
static void saveJson(const json& j) {
    std::lock_guard<std::mutex> lock(g_fileMutex);
    std::ofstream out(g_outPath, std::ios::app | std::ios::binary);
    out << j.dump(-1, ' ', false, json::error_handler_t::replace) << "\n";
}
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
struct Captured {               // v1 과 같은 '보관 1 MiB / 전체는 카운트'
    std::string bytes;
    uint64_t total = 0;
    void add(const std::string& d) {
        total += d.size();
        if (bytes.size() < BODY_LIMIT) bytes.append(d, 0, std::min(d.size(), BODY_LIMIT - bytes.size()));
    }
    json toJson() const { return {{"base64", base64(bytes)}, {"captured", bytes.size()}, {"total", total}, {"truncated", total > bytes.size()}}; }
};
using Headers = std::vector<std::pair<std::string, std::string>>;


// ------------------------------------------------------------
// 인증서 공장 (v2 와 같은 구조, 차이는 ALPN 에서 h2 를 고른다는 것)
// ------------------------------------------------------------
struct CertFactory {
    EVP_PKEY* caKey = nullptr;
    X509* caCert = nullptr;
    EVP_PKEY* leafKey = nullptr;
    SSL_CTX* upstreamCtx = nullptr;
    std::mutex m;
    std::map<std::string, SSL_CTX*> leaves;
};
static CertFactory g_certs;

static std::string tlsError() {
    char b[256]{};
    ERR_error_string_n(ERR_get_error(), b, sizeof(b));
    return b;
}
static void addExt(X509* cert, X509* issuer, int nid, const std::string& value) {
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    if (X509_EXTENSION* e = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.c_str())) {
        X509_add_ext(cert, e, -1);
        X509_EXTENSION_free(e);
    }
}
static void randomSerial(X509* x) {
    unsigned char b[16];
    RAND_bytes(b, sizeof(b));
    b[0] &= 0x7f;
    BIGNUM* bn = BN_bin2bn(b, sizeof(b), nullptr);
    BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x));
    BN_free(bn);
}
static bool makeCa(const std::string& pemPath) {
    g_certs.caKey = EVP_RSA_gen(2048);
    g_certs.leafKey = EVP_RSA_gen(2048);
    X509* c = X509_new();
    X509_set_version(c, 2);
    randomSerial(c);
    X509_gmtime_adj(X509_getm_notBefore(c), -3600);
    X509_gmtime_adj(X509_getm_notAfter(c), 60L * 60 * 24 * 30);
    X509_set_pubkey(c, g_certs.caKey);
    X509_NAME* name = X509_get_subject_name(c);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("WireScope lab v3 CA"), -1, -1, 0);
    X509_set_issuer_name(c, name);
    addExt(c, c, NID_basic_constraints, "critical,CA:TRUE");
    addExt(c, c, NID_key_usage, "critical,keyCertSign,cRLSign");
    addExt(c, c, NID_subject_key_identifier, "hash");
    X509_sign(c, g_certs.caKey, EVP_sha256());
    g_certs.caCert = c;
    FILE* f = fopen(pemPath.c_str(), "wb");
    if (!f) return false;
    PEM_write_X509(f, c);
    fclose(f);
    g_certs.upstreamCtx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(g_certs.upstreamCtx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_default_verify_paths(g_certs.upstreamCtx);
    return true;
}
// 클라이언트가 h2 를 내밀면 h2, 아니면 http/1.1
static int alpnPreferH2(SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned inlen, void*) {
    static const unsigned char mine[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    unsigned char* sel = nullptr;
    if (SSL_select_next_proto(&sel, outlen, mine, sizeof(mine), in, inlen) != OPENSSL_NPN_NEGOTIATED) return SSL_TLSEXT_ERR_NOACK;
    *out = sel;
    return SSL_TLSEXT_ERR_OK;
}
static SSL_CTX* leafFor(const std::string& host) {
    std::lock_guard<std::mutex> lock(g_certs.m);
    if (auto it = g_certs.leaves.find(host); it != g_certs.leaves.end()) return it->second;
    X509* x = X509_new();
    X509_set_version(x, 2);
    randomSerial(x);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 7);
    X509_set_pubkey(x, g_certs.leafKey);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(x), "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(host.c_str()), -1, -1, 0);
    X509_set_issuer_name(x, X509_get_subject_name(g_certs.caCert));
    unsigned char ip[16];
    bool numeric = inet_pton(AF_INET, host.c_str(), ip) == 1 || inet_pton(AF_INET6, host.c_str(), ip) == 1;
    addExt(x, g_certs.caCert, NID_subject_alt_name, (numeric ? "IP:" : "DNS:") + host);
    addExt(x, g_certs.caCert, NID_basic_constraints, "critical,CA:FALSE");
    addExt(x, g_certs.caCert, NID_ext_key_usage, "serverAuth");
    X509_sign(x, g_certs.caKey, EVP_sha256());
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(ctx, x);
    SSL_CTX_use_PrivateKey(ctx, g_certs.leafKey);
    SSL_CTX_set_alpn_select_cb(ctx, alpnPreferH2, nullptr);
    X509_free(x);
    g_certs.leaves[host] = ctx;
    return ctx;
}


// ------------------------------------------------------------
// h2 프레임 파서 (한 방향당 하나)
//   TLS 레코드 경계 != h2 프레임 경계. 프레임이 레코드 두 개에 걸쳐 올 수도,
//   레코드 하나에 프레임 여러 개가 들어 있을 수도 있다.
//   -> v1 의 Reader 처럼 buf 에 쌓아두고 '완성된 프레임'만 꺼낸다.
// ------------------------------------------------------------
static const char* PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";   // 클라이언트가 맨 처음 보내는 24바이트 고정 문자열
static const char* FRAME_NAMES[] = {"DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"};

struct Frame {
    uint32_t length;
    uint8_t type, flags;
    uint32_t stream;
    std::string payload;
};

static uint32_t be24(const std::string& s, size_t p) { return (uint32_t(uint8_t(s[p])) << 16) | (uint32_t(uint8_t(s[p + 1])) << 8) | uint8_t(s[p + 2]); }
static uint32_t be32(const std::string& s, size_t p) { return (be24(s, p) << 8) | uint8_t(s[p + 3]); }
static uint16_t be16(const std::string& s, size_t p) { return uint16_t((uint8_t(s[p]) << 8) | uint8_t(s[p + 1])); }

static std::string flagNames(uint8_t type, uint8_t f) {
    std::string out;
    auto add = [&](const char* n) { out += out.empty() ? n : std::string("|") + n; };
    if (type == 4 || type == 6) { if (f & 0x1) add("ACK"); return out; }   // SETTINGS/PING 의 0x1 은 ACK
    if (f & 0x1) add("END_STREAM");
    if (f & 0x4) add("END_HEADERS");
    if (f & 0x8) add("PADDED");
    if (f & 0x20) add("PRIORITY");
    return out;
}

struct Direction {
    const char* label;                 // "C->S" or "S->C"
    std::string buf;
    bool needPreface;
    nghttp2_hd_inflater* hpack = nullptr;   // 이 방향의 HPACK 동적 테이블 상태
    uint32_t blockStream = 0;               // CONTINUATION 을 기다리는 중인 stream
    std::string block;                      // 모으는 중인 header block 조각들
    bool blockEndStream = false;
};

// 완성된 프레임을 하나씩 꺼낸다. 아직 덜 왔으면 false.
static bool nextFrame(Direction& d, Frame& f, std::string& error) {
    if (d.needPreface) {
        if (d.buf.size() < 24) return false;
        if (d.buf.compare(0, 24, PREFACE) != 0) { error = "missing HTTP/2 client preface"; return false; }
        d.buf.erase(0, 24);
        d.needPreface = false;
    }
    if (d.buf.size() < 9) return false;
    f.length = be24(d.buf, 0);
    if (d.buf.size() < 9 + f.length) return false;
    f.type = uint8_t(d.buf[3]);
    f.flags = uint8_t(d.buf[4]);
    f.stream = be32(d.buf, 5) & 0x7fffffff;           // 맨 위 1비트(R)는 예약 비트라 버린다
    f.payload = d.buf.substr(9, f.length);
    d.buf.erase(0, 9 + f.length);
    return true;
}

// 프레임 하나를 사람이 읽을 수 있게 (제어 프레임은 payload 도 조금 풀어서)
static json describeFrame(const char* dir, const Frame& f, int64_t t) {
    json j = {{"t", t}, {"dir", dir}, {"type", f.type < 10 ? FRAME_NAMES[f.type] : "UNKNOWN"}, {"stream", f.stream},
              {"length", f.length}, {"flags", flagNames(f.type, f.flags)}};
    if (f.type == 4 && !(f.flags & 1)) {                     // SETTINGS: [id 2B][value 4B] 반복
        static const char* ids[] = {"", "HEADER_TABLE_SIZE", "ENABLE_PUSH", "MAX_CONCURRENT_STREAMS", "INITIAL_WINDOW_SIZE", "MAX_FRAME_SIZE", "MAX_HEADER_LIST_SIZE"};
        json s = json::object();
        for (size_t p = 0; p + 6 <= f.payload.size(); p += 6) {
            uint16_t id = be16(f.payload, p);
            s[id >= 1 && id <= 6 ? ids[id] : std::to_string(id)] = be32(f.payload, p + 2);
        }
        j["settings"] = s;
    } else if (f.type == 8 && f.payload.size() == 4) {       // WINDOW_UPDATE: 얼마나 더 보내도 되는지
        j["increment"] = be32(f.payload, 0) & 0x7fffffff;
    } else if ((f.type == 3 || f.type == 7) && f.payload.size() >= 4) {   // RST_STREAM / GOAWAY 에러 코드
        j["errorCode"] = be32(f.payload, f.type == 3 ? 0 : 4);
    }
    return j;
}


// ------------------------------------------------------------
// 두 TLS 세션 사이를 바이트 그대로 릴레이하면서 프레임 관찰
//   SSL_pending: OpenSSL 내부에 이미 복호화돼 쌓여 있는 바이트. 소켓은 조용해도 읽을 게 있을 수 있어서
//                select 전에 먼저 확인해야 한다 (안 그러면 데이터가 있는데도 멈춰 있음).
// ------------------------------------------------------------
// stream 하나 = 요청/응답 한 쌍
struct H2Stream {
    uint32_t id = 0;
    Headers requestHeaders, responseHeaders, requestTrailers, responseTrailers, informational;
    Captured request, response;
    json timeline = json::array();
    bool requestEnded = false, responseEnded = false, saved = false;
    std::string error;
};

struct Tunnel {
    uint64_t id;
    int64_t started;
    std::string host;
    uint16_t port;
    std::string alpn;
    json frames = json::array();
    std::map<uint32_t, json> streams;       // stream id -> {frames, dataBytes C->S/S->C}
    std::string error;
    std::map<uint32_t, H2Stream> h2;        // 단계 2: stream 별 요청/응답
};

static std::string pseudo(const Headers& h, const char* name) {
    for (auto& [k, v] : h)
        if (k == name) return v;
    return "";
}

static void saveStream(Tunnel& t, H2Stream& s) {
    if (s.saved) return;
    s.saved = true;
    std::string state = !s.error.empty() ? "error" : (s.requestEnded && s.responseEnded) ? "complete" : "incomplete";
    saveJson({{"kind", "h2-stream"}, {"connection", t.id}, {"stream", s.id}, {"host", t.host}, {"port", t.port},
              {"method", pseudo(s.requestHeaders, ":method")}, {"authority", pseudo(s.requestHeaders, ":authority")},
              {"path", pseudo(s.requestHeaders, ":path")}, {"status", std::atoi(pseudo(s.responseHeaders, ":status").c_str())},
              {"state", state}, {"error", s.error}, {"requestHeaders", s.requestHeaders}, {"responseHeaders", s.responseHeaders},
              {"requestTrailers", s.requestTrailers}, {"responseTrailers", s.responseTrailers}, {"informational", s.informational},
              {"request", s.request.toJson()}, {"response", s.response.toJson()}, {"timeline", s.timeline}});
    printf("[v3] #%llu stream %u  %s %s -> %s  req %llu B  res %llu B  (%s)\n", (unsigned long long)t.id, s.id,
           pseudo(s.requestHeaders, ":method").c_str(), pseudo(s.requestHeaders, ":path").c_str(), pseudo(s.responseHeaders, ":status").c_str(),
           (unsigned long long)s.request.total, (unsigned long long)s.response.total, state.c_str());
}

// HPACK 블록 하나를 풀어서 헤더 목록으로. 실패하면 이 방향의 테이블 상태를 더 믿을 수 없다.
static bool inflate(Direction& d, const std::string& block, Headers& out) {
    auto* in = reinterpret_cast<const uint8_t*>(block.data());
    size_t left = block.size();
    for (;;) {
        nghttp2_nv nv;
        int flags = 0;
        nghttp2_ssize used = nghttp2_hd_inflate_hd3(d.hpack, &nv, &flags, in, left, 1);
        if (used < 0) return false;
        in += used;
        left -= size_t(used);
        if (flags & NGHTTP2_HD_INFLATE_EMIT)
            out.emplace_back(std::string(reinterpret_cast<char*>(nv.name), nv.namelen), std::string(reinterpret_cast<char*>(nv.value), nv.valuelen));
        if (flags & NGHTTP2_HD_INFLATE_FINAL) {
            nghttp2_hd_inflate_end_headers(d.hpack);
            return true;
        }
        if (used == 0 && left == 0) return true;
    }
}

// 헤더 블록이 완성됐을 때: 요청 헤더 / 응답 헤더 / 1xx / trailer 중 어디에 넣을지 결정
static void onHeaderBlock(Tunnel& t, Direction& d, uint32_t stream, bool endStream) {
    Headers hs;
    H2Stream& s = t.h2[stream];
    s.id = stream;
    if (!inflate(d, d.block, hs)) {
        t.error = std::string("HPACK decode failed (") + d.label + ")";
        return;
    }
    bool c2s = d.label[0] == 'C';
    int64_t now = nowMs() - t.started;
    if (c2s) {
        (s.requestHeaders.empty() ? s.requestHeaders : s.requestTrailers) = hs;
        s.timeline.push_back({{"t", now}, {"event", s.requestTrailers.empty() ? "request.headers" : "request.trailers"}});
    } else {
        std::string status = pseudo(hs, ":status");
        if (!status.empty() && status[0] == '1') {
            s.informational.insert(s.informational.end(), hs.begin(), hs.end());   // 100 Continue 등
        } else if (s.responseHeaders.empty()) {
            s.responseHeaders = hs;
            s.timeline.push_back({{"t", now}, {"event", "response.headers"}});
        } else {
            s.responseTrailers = hs;
            s.timeline.push_back({{"t", now}, {"event", "response.trailers"}});
        }
    }
    if (endStream) {
        (c2s ? s.requestEnded : s.responseEnded) = true;
        s.timeline.push_back({{"t", now}, {"event", c2s ? "request.end" : "response.end"}});
    }
    if (s.responseEnded) saveStream(t, s);
}

// payload 앞뒤의 padding / priority 필드를 걷어낸 '진짜 내용'
static std::string unpad(const Frame& f, size_t skip) {
    size_t start = 0, pad = 0;
    if (f.flags & 0x8) {                                 // PADDED: 첫 바이트 = padding 길이
        if (f.payload.empty()) return "";
        pad = uint8_t(f.payload[0]);
        start = 1;
    }
    start += skip;
    if (start + pad > f.payload.size()) return "";
    return f.payload.substr(start, f.payload.size() - start - pad);
}

// 단계 2: 프레임을 stream 상태에 반영
static void track(Tunnel& t, Direction& d, const Frame& f) {
    bool c2s = d.label[0] == 'C';
    if (f.type == 1) {                                                    // HEADERS
        d.block = unpad(f, (f.flags & 0x20) ? 5 : 0);                     // PRIORITY 플래그면 5바이트(의존성+가중치) 건너뜀
        d.blockStream = f.stream;
        d.blockEndStream = f.flags & 0x1;
        if (f.flags & 0x4) onHeaderBlock(t, d, f.stream, d.blockEndStream);
    } else if (f.type == 9 && f.stream == d.blockStream) {                // CONTINUATION: 같은 블록 이어붙이기
        d.block += f.payload;
        if (f.flags & 0x4) onHeaderBlock(t, d, f.stream, d.blockEndStream);
    } else if (f.type == 0) {                                             // DATA
        H2Stream& s = t.h2[f.stream];
        s.id = f.stream;
        (c2s ? s.request : s.response).add(unpad(f, 0));
        if (f.flags & 0x1) {
            (c2s ? s.requestEnded : s.responseEnded) = true;
            s.timeline.push_back({{"t", nowMs() - t.started}, {"event", c2s ? "request.end" : "response.end"}});
            if (s.responseEnded) saveStream(t, s);
        }
    } else if (f.type == 3) {                                             // RST_STREAM: 이 stream 만 취소
        H2Stream& s = t.h2[f.stream];
        s.id = f.stream;
        s.error = std::string("RST_STREAM from ") + (c2s ? "client" : "server") + " code " + std::to_string(f.payload.size() >= 4 ? be32(f.payload, 0) : 0);
        saveStream(t, s);
    }
}

static void onFrame(Tunnel& t, const char* dir, const Frame& f) {
    json d = describeFrame(dir, f, nowMs() - t.started);
    printf("[v3] #%llu %s %-13s stream %-3u len %-6u %s\n", (unsigned long long)t.id, dir, d["type"].get<std::string>().c_str(), f.stream, f.length,
           d["flags"].get<std::string>().c_str());
    if (t.frames.size() < 2000) t.frames.push_back(d);
    if (f.stream) {
        json& s = t.streams[f.stream];
        if (s.is_null()) s = {{"stream", f.stream}, {"frames", 0}, {"dataClientToServer", 0}, {"dataServerToClient", 0}};
        s["frames"] = s["frames"].get<int>() + 1;
        if (f.type == 0) {
            const char* key = dir[0] == 'C' ? "dataClientToServer" : "dataServerToClient";
            s[key] = s[key].get<uint64_t>() + f.length;
        }
    }
}

struct Inflaters {          // 방향별 HPACK 해제기 (함수 끝나면 정리)
    Direction& a;
    Direction& b;
    Inflaters(Direction& x, Direction& y) : a(x), b(y) {
        nghttp2_hd_inflate_new(&a.hpack);
        nghttp2_hd_inflate_new(&b.hpack);
    }
    ~Inflaters() {
        nghttp2_hd_inflate_del(a.hpack);
        nghttp2_hd_inflate_del(b.hpack);
    }
};

static void relayH2(Tunnel& t, sock_t cfd, SSL* cs, sock_t ufd, SSL* us) {
    Direction c2s{"C->S", {}, true}, s2c{"S->C", {}, false};
    Inflaters hpack(c2s, s2c);
    char buf[16384];
    for (;;) {
        bool cReady = SSL_pending(cs) > 0, uReady = SSL_pending(us) > 0;
        if (!cReady && !uReady) {
            fd_set r;
            FD_ZERO(&r);
            FD_SET(cfd, &r);
            FD_SET(ufd, &r);
            timeval tv{30, 0};
            if (select(int(std::max(cfd, ufd)) + 1, &r, nullptr, nullptr, &tv) <= 0) return;
            cReady = FD_ISSET(cfd, &r);
            uReady = FD_ISSET(ufd, &r);
        }
        for (auto [ready, from, to, dir] : {std::tuple{cReady, cs, us, &c2s}, std::tuple{uReady, us, cs, &s2c}}) {
            if (!ready) continue;
            int n = SSL_read(from, buf, sizeof(buf));
            if (n <= 0) return;                              // 한쪽이 닫으면 끝
            for (int sent = 0; sent < n;) {                  // 받은 평문 그대로 반대쪽으로 (반대쪽 세션 키로 재암호화)
                int k = SSL_write(to, buf + sent, n - sent);
                if (k <= 0) return;
                sent += k;
            }
            dir->buf.append(buf, size_t(n));
            Frame f;
            while (nextFrame(*dir, f, t.error)) {
                onFrame(t, dir->label, f);
                track(t, *dir, f);
            }
            if (!t.error.empty()) return;
        }
    }
}


// ------------------------------------------------------------
// 연결 처리: CONNECT 만 받는다 (h2 는 사실상 항상 TLS 위에서 쓰이니까)
// ------------------------------------------------------------
static void handleClient(sock_t client) {
    lab::setTimeout(client, 30);
    std::string head;
    char b[4096];
    while (head.find("\r\n\r\n") == std::string::npos) {   // CONNECT 헤드만 읽음 (body 없음)
        int n = int(recv(client, b, sizeof(b), 0));
        if (n <= 0 || head.size() > 16384) { lab::closeSock(client); return; }
        head.append(b, size_t(n));
    }
    if (head.rfind("CONNECT ", 0) != 0 || head.size() != head.find("\r\n\r\n") + 4) {   // 헤드 뒤에 바이트가 더 왔으면(pre-read) 미지원
        lab::sendAll(client, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        lab::closeSock(client);
        return;
    }
    std::string target = head.substr(8, head.find(' ', 8) - 8);
    size_t colon = target.rfind(':');
    Tunnel t{g_nextId++, nowMs(), target.substr(0, colon), uint16_t(std::stoi(target.substr(colon + 1))), "", json::array(), {}, ""};

    sock_t up = lab::connectTo(t.host, t.port);
    if (up == BAD_SOCK) {
        lab::sendAll(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
        lab::closeSock(client);
        return;
    }
    lab::sendAll(client, "HTTP/1.1 200 Connection Established\r\n\r\n");

    SSL* cs = SSL_new(leafFor(t.host));
    SSL_set_fd(cs, int(client));
    SSL* us = SSL_new(g_certs.upstreamCtx);
    SSL_set_fd(us, int(up));
    if (SSL_accept(cs) == 1) {
        // 클라이언트와 고른 프로토콜을 서버에도 똑같이 요청 -> 양쪽이 같은 언어를 써야 바이트를 그대로 넘길 수 있다
        const unsigned char* sel = nullptr;
        unsigned selLen = 0;
        SSL_get0_alpn_selected(cs, &sel, &selLen);
        t.alpn.assign(reinterpret_cast<const char*>(sel ? sel : reinterpret_cast<const unsigned char*>("")), selLen);
        unsigned char wire[16] = {uint8_t(selLen)};
        memcpy(wire + 1, sel, selLen);
        SSL_set_alpn_protos(us, wire, selLen + 1);
        SSL_set_tlsext_host_name(us, t.host.c_str());
        SSL_set1_host(us, t.host.c_str());
        if (SSL_connect(us) == 1) {
            const unsigned char* got = nullptr;
            unsigned gotLen = 0;
            SSL_get0_alpn_selected(us, &got, &gotLen);
            if (gotLen != selLen || memcmp(got, sel, selLen) != 0) t.error = "upstream negotiated a different ALPN";
            else if (t.alpn == "h2") relayH2(t, client, cs, up, us);
            else t.error = "client did not negotiate h2 (v3 only observes h2)";
        } else {
            t.error = "upstream TLS: " + tlsError();
        }
    } else {
        t.error = "client TLS: " + tlsError();
    }
    for (auto& [id, s] : t.h2) saveStream(t, s);     // 끝까지 못 간 stream 도 'incomplete' 로 남긴다
    json streams = json::array();
    for (auto& [id, s] : t.streams) streams.push_back(s);
    saveJson({{"id", t.id}, {"time", t.started}, {"kind", "h2-connection"}, {"host", t.host}, {"port", t.port}, {"alpn", t.alpn},
              {"error", t.error}, {"streams", streams}, {"frames", t.frames}});
    printf("[v3] #%llu %s:%u done, %zu streams, %zu frames%s%s\n", (unsigned long long)t.id, t.host.c_str(), t.port, t.streams.size(),
           t.frames.size(), t.error.empty() ? "" : ", error: ", t.error.c_str());
    SSL_free(cs);
    SSL_free(us);
    lab::closeSock(up);
    lab::closeSock(client);
}


int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    if (argc > 1) g_outPath = argv[1];
    lab::netInit();
    std::string caPath = g_outPath + ".ca.pem";
    if (!makeCa(caPath)) {
        printf("CA 파일을 쓸 수 없음: %s\n", caPath.c_str());
        return 1;
    }
    sock_t listener = lab::listenLocal(LISTEN_PORT);
    if (listener == BAD_SOCK) {
        printf("listen 실패 (포트 %u 사용 중?)\n", LISTEN_PORT);
        return 1;
    }
    printf("[v3] 127.0.0.1:%u 대기, 기록 -> %s\n     예) curl --http2 -x http://127.0.0.1:%u --cacert %s https://example.com/\n", LISTEN_PORT,
           g_outPath.c_str(), LISTEN_PORT, caPath.c_str());
    for (;;) {
        sock_t c = accept(listener, nullptr, nullptr);
        if (c == BAD_SOCK) continue;
        std::thread(handleClient, c).detach();
    }
}
