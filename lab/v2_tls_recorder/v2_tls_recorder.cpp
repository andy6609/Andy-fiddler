/*
============================================================
 v2_tls_recorder  —  HTTPS: 터널을 '통과'시킬 것인가, '끊고' 볼 것인가
============================================================
 목적: v1 은 평문 HTTP 만 봤다. 요즘 트래픽은 거의 다 HTTPS 라서
       클라이언트는 프록시에게 이렇게 말한다:
         CONNECT api.example.com:443 HTTP/1.1      "이 주소로 TCP 터널 좀 뚫어줘"
       프록시가 "200 Connection Established" 를 보내는 순간부터 그 연결 위로는
       TLS(암호화된 바이트)가 흐른다.

 [v2 단계 1 — passthrough]  (기본 모드)
   CONNECT -> upstream TCP 연결 -> 200 -> 양방향 blind 릴레이 (select 로 두 소켓 감시)
   내용은 못 보지만, 그래도 '관찰할 수 있는 것'이 있다. 그걸 다 기록한다:
     - 방향별 바이트 수, 타이밍
     - 첫 바이트들 = TLS 레코드 헤더 (0x16 = Handshake, 0x17 = Application Data ...)
     - ClientHello 안의 SNI(server_name) — 암호화 '전'에 평문으로 지나가는 host 이름!

 [v2 단계 2 — MITM]  (--mitm)
   CONNECT -> 200 -> *프록시가 직접 TLS 를 양쪽으로 끊는다* -> 평문 HTTP 를 v1 로직으로 기록

     curl  <== TLS 세션1 ==>  [v2]  <== TLS 세션2 ==>  서버
           (v2 가 서버 역할)          (v2 가 클라 역할)

   - 세션1: v2 가 '그 host 의 서버인 척' 해야 한다 -> host 별 leaf 인증서를 즉석에서 만들고
            내가 만든 CA 로 서명. 클라이언트는 그 CA 를 믿어야 함 (curl --cacert / OS 신뢰 저장소).
   - 세션2: v2 가 평범한 TLS 클라이언트로 진짜 서버에 접속. 서버 인증서는 '제대로' 검증한다.
            (검증 안 하면 프록시 자체가 다른 MITM 에 뚫린다)

 ★ 단계 2의 핵심 설계 = Stream 추상화 (local-proxy-lab proxy_v4 와 같은 아이디어)
     PlainStream : recv/send          <- 평문 HTTP 경로
     TlsStream   : SSL_read/SSL_write <- 복호화된 HTTPS 경로
   Reader / body 전달 함수들이 Stream 만 보게 바꿨더니 v1 의 HTTP 파싱 코드가
   한 줄도 안 바뀌고 TLS 안쪽에서도 그대로 돈다.

 ALPN 에서 일부러 http/1.1 만 받는다:
   curl --http2 처럼 h2 를 원하는 클라이언트도 여기선 HTTP/1.1 로 내려온다.
   h2 를 그대로 보려면 프레임/스트림을 이해해야 함 -> v3.

 한계 (본체에서 해결한 것들):
   - CONNECT 헤드와 같이 읽힌 ClientHello(pre-read) 는 MITM 모드에서 미지원.
     proxy_v4 는 커스텀 BIO 로 선주입했고, WireScope 본체는 에러로 처리.
   - CA 는 실행할 때마다 새로 만든다 (본체는 파일로 저장해서 재사용 + 개인키 권한 제한).
============================================================
*/

#include "lab_net.hpp"

#include "json.hpp"   // nlohmann/json (third_party). JSON 직렬화는 직접 안 짜고 라이브러리로.

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using json = nlohmann::json;

static const uint16_t LISTEN_PORT = 18082;
static const size_t BODY_LIMIT = 1024 * 1024;   // 방향별 보관 한도 (WireScope 와 같은 값)
static bool g_mitm = false;


// ------------------------------------------------------------
// Stream: "바이트를 읽고 쓰는 것" 의 공통 모양
//   평문 소켓이든 TLS 든 위쪽(HTTP 파서)은 차이를 모르게 한다.
// ------------------------------------------------------------
struct Stream {
    virtual ~Stream() = default;
    virtual int read(char* p, int n) = 0;                 // >0 읽은 수, 0 끝, <0 에러
    virtual bool write(const char* p, size_t n) = 0;
    bool write(const std::string& s) { return write(s.data(), s.size()); }
};
struct PlainStream : Stream {
    sock_t s;
    explicit PlainStream(sock_t sock) : s(sock) {}
    int read(char* p, int n) override { return int(recv(s, p, n, 0)); }
    bool write(const char* p, size_t n) override { return lab::sendAll(s, p, n); }
};
struct TlsStream : Stream {
    SSL* ssl;
    explicit TlsStream(SSL* x) : ssl(x) {}
    int read(char* p, int n) override { return SSL_read(ssl, p, n); }       // 복호화된 평문이 나온다
    bool write(const char* p, size_t n) override {                         // 평문을 넣으면 암호화돼서 나간다
        while (n > 0) {
            int k = SSL_write(ssl, p, int(std::min<size_t>(n, 16384)));
            if (k <= 0) return false;
            p += k;
            n -= size_t(k);
        }
        return true;
    }
};


// ------------------------------------------------------------
// Reader: v1 과 같은데 소켓 대신 Stream 을 읽는다
// ------------------------------------------------------------
struct Reader {
    Stream* io;
    std::string buf;

    bool fill() {
        char tmp[16384];
        int n = io->read(tmp, sizeof(tmp));
        if (n <= 0) return false;
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
            if (buf.size() > 64 * 1024) return false;
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
// HTTP 헤드 + 유틸 (v1 과 동일)
// ------------------------------------------------------------
using Headers = std::vector<std::pair<std::string, std::string>>;
struct Head {
    std::string startLine;
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
static std::string headerGet(const Headers& h, const std::string& name) {
    for (auto& [k, v] : h)
        if (lower(k) == lower(name)) return v;
    return "";
}
static void headerErase(Headers& h, const std::string& name) {
    h.erase(std::remove_if(h.begin(), h.end(), [&](auto& kv) { return lower(kv.first) == lower(name); }), h.end());
}
static bool readHead(Reader& r, Head& h) {
    h = {};
    if (!r.line(h.startLine) || h.startLine.empty()) return false;
    for (int i = 0; i < 200; i++) {
        std::string line;
        if (!r.line(line)) return false;
        if (line.empty()) return true;
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
// Captured / Flow / 저장 (v1 + tls 정보)
// ------------------------------------------------------------
struct Captured {
    std::string bytes;
    uint64_t total = 0;
    void add(const std::string& data) {
        total += data.size();
        if (bytes.size() < BODY_LIMIT) bytes.append(data, 0, std::min(data.size(), BODY_LIMIT - bytes.size()));
    }
    json toJson() const {
        return {{"base64", base64(bytes)}, {"captured", bytes.size()}, {"total", total}, {"truncated", total > bytes.size()}};
    }
};

struct Flow {
    uint64_t id = 0;
    int64_t started = 0;
    std::string method, scheme = "http", host, path, error, tls;
    uint16_t port = 0;
    int status = 0;
    Headers requestHeaders, responseHeaders, responseTrailers;
    Captured request, response;
    json timeline = json::array();
    json endpoints = json::array();
    json observed = json::object();     // 터널에서 '밖에서도 보이는 것' (TLS 레코드, SNI, 협상 결과)

    void mark(const char* event) { timeline.push_back({{"t", nowMs() - started}, {"event", event}}); }
    json toJson() const {
        return {{"id", id}, {"time", started}, {"method", method}, {"scheme", scheme}, {"host", host}, {"port", port},
                {"path", path}, {"status", status}, {"error", error}, {"tls", tls}, {"requestHeaders", requestHeaders},
                {"responseHeaders", responseHeaders}, {"responseTrailers", responseTrailers}, {"request", request.toJson()},
                {"response", response.toJson()}, {"timeline", timeline}, {"endpoints", endpoints}, {"observed", observed}};
    }
};

static std::atomic<uint64_t> g_nextId{1};
static std::mutex g_fileMutex;
static std::string g_outPath = "flows.jsonl";

static void saveFlow(const Flow& f) {
    std::lock_guard<std::mutex> lock(g_fileMutex);
    std::ofstream out(g_outPath, std::ios::app | std::ios::binary);
    out << f.toJson().dump(-1, ' ', false, json::error_handler_t::replace) << "\n";
}
static Flow newFlow() {
    Flow f;
    f.id = g_nextId++;
    f.started = nowMs();
    return f;
}


// ------------------------------------------------------------
// body 전달 (v1 과 동일, 쓰는 쪽이 Stream)
// ------------------------------------------------------------
static bool forwardExact(Reader& from, Stream& to, uint64_t n, Captured& cap) {
    while (n > 0) {
        std::string chunk;
        if (!from.exact(size_t(std::min<uint64_t>(n, 16384)), chunk)) return false;
        if (!to.write(chunk)) return false;
        cap.add(chunk);
        n -= chunk.size();
    }
    return true;
}
static bool forwardChunked(Reader& from, Stream& to, Captured& cap, Headers* trailers) {
    for (;;) {
        std::string sizeLine;
        if (!from.line(sizeLine)) return false;
        to.write(sizeLine + "\r\n");
        uint64_t n = std::stoull(sizeLine.substr(0, sizeLine.find(';')), nullptr, 16);
        if (n == 0) {
            for (;;) {
                std::string line;
                if (!from.line(line)) return false;
                to.write(line + "\r\n");
                if (line.empty()) return true;
                size_t c = line.find(':');
                if (trailers && c != std::string::npos) trailers->emplace_back(line.substr(0, c), trim(line.substr(c + 1)));
            }
        }
        if (!forwardExact(from, to, n, cap)) return false;
        std::string crlf;
        if (!from.exact(2, crlf) || crlf != "\r\n") return false;
        to.write(crlf);
    }
}
static void forwardUntilClose(Reader& from, Stream& to, Captured& cap) {
    do {
        if (!from.buf.empty()) {
            to.write(from.buf);
            cap.add(from.buf);
            from.buf.clear();
        }
    } while (from.fill());
}


// ------------------------------------------------------------
// TLS 레코드 헤더 / SNI (단계 1)
//   [content type 1B][version 2B][length 2B][ ... ]
//     0x14 ChangeCipherSpec / 0x15 Alert / 0x16 Handshake / 0x17 ApplicationData
//   첫 Handshake 메시지(ClientHello)는 암호화 전이라 SNI 확장에 host 이름이 평문으로 있다.
// ------------------------------------------------------------
static uint16_t be16(const std::string& s, size_t p) { return uint16_t((uint8_t(s[p]) << 8) | uint8_t(s[p + 1])); }

static std::string findSni(const std::string& rec) {
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
        if (type == 0 && p + 5 <= end) {
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

// 양방향 blind 릴레이 (select 로 두 소켓을 동시에 감시)
static void tunnel(sock_t client, std::string& preRead, sock_t up, Flow& flow) {
    if (!preRead.empty()) {                      // CONNECT 헤드와 같이 읽혀버린 ClientHello
        lab::sendAll(up, preRead);
        flow.request.add(preRead);
        preRead.clear();
    }
    char buf[16384];
    for (;;) {
        fd_set r;
        FD_ZERO(&r);
        FD_SET(client, &r);
        FD_SET(up, &r);
        timeval tv{30, 0};
        int n = select(int(std::max(client, up)) + 1, &r, nullptr, nullptr, &tv);
        if (n <= 0) break;
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
// 단계 2: 인증서 공장 (CA 1개 + host 별 leaf)
//
//   CA   : "WireScope lab v2 CA" — 자기가 자기를 서명(self-signed). CA:TRUE.
//   leaf : CN/SAN = 접속하려는 host. CA 가 서명. CA:FALSE, 용도 serverAuth.
//   클라이언트가 검사하는 것 = (1) 체인이 믿는 CA 까지 이어지나 (2) SAN 에 host 가 있나 (3) 기간
// ------------------------------------------------------------
struct CertFactory {
    EVP_PKEY* caKey = nullptr;
    X509* caCert = nullptr;
    EVP_PKEY* leafKey = nullptr;          // leaf 들은 키 하나를 같이 씀 (키 생성이 느려서)
    SSL_CTX* upstreamCtx = nullptr;       // 세션2(진짜 서버 쪽) 용
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
    X509_EXTENSION* e = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.c_str());
    if (e) {
        X509_add_ext(cert, e, -1);
        X509_EXTENSION_free(e);
    }
}
static void randomSerial(X509* x) {
    unsigned char b[16];
    RAND_bytes(b, sizeof(b));
    b[0] &= 0x7f;                          // 양수로
    BIGNUM* bn = BN_bin2bn(b, sizeof(b), nullptr);
    BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x));
    BN_free(bn);
}

static bool makeCa(const std::string& pemPath) {
    g_certs.caKey = EVP_RSA_gen(2048);
    g_certs.leafKey = EVP_RSA_gen(2048);
    X509* c = X509_new();
    X509_set_version(c, 2);                                   // 2 = X.509 v3 (0부터 셈)
    randomSerial(c);
    X509_gmtime_adj(X509_getm_notBefore(c), -3600);           // 시계 오차 대비 1시간 전부터
    X509_gmtime_adj(X509_getm_notAfter(c), 60L * 60 * 24 * 30);
    X509_set_pubkey(c, g_certs.caKey);
    X509_NAME* name = X509_get_subject_name(c);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("WireScope lab v2 CA"), -1, -1, 0);
    X509_set_issuer_name(c, name);                            // self-signed: 발급자 = 자기 자신
    addExt(c, c, NID_basic_constraints, "critical,CA:TRUE");
    addExt(c, c, NID_key_usage, "critical,keyCertSign,cRLSign");
    addExt(c, c, NID_subject_key_identifier, "hash");
    X509_sign(c, g_certs.caKey, EVP_sha256());
    g_certs.caCert = c;

    // 클라이언트에게 줄 건 '인증서'만. 개인키는 메모리에만.
    // Windows 함정: fopen 한 FILE* 를 OpenSSL DLL 의 PEM_write_X509(FILE*) 에 넘기면
    //   앱과 DLL 의 C 런타임이 달라 "OPENSSL_Uplink: no OPENSSL_Applink" 로 프로세스가 중단된다.
    //   -> OpenSSL 은 메모리 BIO 에만 쓰게 하고, 파일은 우리 쪽 C++ 스트림으로 쓴다 (본체 tls.cpp 와 같은 방식).
    BIO* mem = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mem, c);
    char* pemData = nullptr;
    long pemSize = BIO_get_mem_data(mem, &pemData);
    std::ofstream pemFile(pemPath, std::ios::binary);
    pemFile.write(pemData, pemSize);
    BIO_free(mem);
    if (!pemFile) return false;

    g_certs.upstreamCtx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(g_certs.upstreamCtx, SSL_VERIFY_PEER, nullptr);   // 진짜 서버 인증서는 반드시 검증
    SSL_CTX_set_default_verify_paths(g_certs.upstreamCtx);                // OS/OpenSSL 기본 CA 번들 (SSL_CERT_FILE 로 바꿀 수 있음)
    return true;
}

// ALPN: 클라이언트가 내민 프로토콜 목록에서 http/1.1 만 고른다 (h2 는 v3 에서)
static int alpnHttp11(SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned inlen, void*) {
    static const unsigned char mine[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    unsigned char* sel = nullptr;
    if (SSL_select_next_proto(&sel, outlen, mine, sizeof(mine), in, inlen) != OPENSSL_NPN_NEGOTIATED) return SSL_TLSEXT_ERR_NOACK;
    *out = sel;
    return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX* leafFor(const std::string& host) {
    std::lock_guard<std::mutex> lock(g_certs.m);
    auto it = g_certs.leaves.find(host);
    if (it != g_certs.leaves.end()) return it->second;
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
    addExt(x, g_certs.caCert, NID_subject_alt_name, (numeric ? "IP:" : "DNS:") + host);   // 요즘 클라는 CN 말고 SAN 을 본다
    addExt(x, g_certs.caCert, NID_basic_constraints, "critical,CA:FALSE");
    addExt(x, g_certs.caCert, NID_ext_key_usage, "serverAuth");
    X509_sign(x, g_certs.caKey, EVP_sha256());

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(ctx, x);
    SSL_CTX_use_PrivateKey(ctx, g_certs.leafKey);
    SSL_CTX_set_alpn_select_cb(ctx, alpnHttp11, nullptr);
    X509_free(x);
    g_certs.leaves[host] = ctx;
    return ctx;
}


// ------------------------------------------------------------
// upstream: 평문이면 소켓, MITM 안쪽이면 소켓 + SSL
// ------------------------------------------------------------
struct Upstream {
    sock_t sock = BAD_SOCK;
    SSL* ssl = nullptr;
    std::unique_ptr<Stream> io;
    Reader reader{nullptr, {}};
    std::string host;
    uint16_t port = 0;

    void close() {
        if (ssl) SSL_free(ssl);
        ssl = nullptr;
        lab::closeSock(sock);
        sock = BAD_SOCK;
        io.reset();
    }
    bool connectPlain(const std::string& h, uint16_t p) {
        close();
        sock = lab::connectTo(h, p);
        if (sock == BAD_SOCK) return false;
        lab::setTimeout(sock, 30);
        io = std::make_unique<PlainStream>(sock);
        reader = Reader{io.get(), {}};
        host = h;
        port = p;
        return true;
    }
    ~Upstream() { close(); }
};

static void handleConnect(sock_t client, Reader& cr, Flow& flow, const std::string& target);


// ------------------------------------------------------------
// HTTP 요청 루프 — 평문 프록시 요청이든, MITM 으로 복호화된 HTTPS 든 같은 코드
//   tls == false : 요청줄이 absolute-form (http://host/path), upstream 은 요청마다 결정
//   tls == true  : 요청줄이 origin-form (/path), upstream 은 CONNECT 한 host 로 고정
// ------------------------------------------------------------
static void httpLoop(sock_t client, Reader& cr, Stream& cw, Upstream& up, bool tls, const std::string& tlsVersion) {
    Head req;
    while (readHead(cr, req)) {
        Flow flow = newFlow();
        flow.requestHeaders = req.headers;
        flow.mark("request.headers");

        size_t s1 = req.startLine.find(' '), s2 = req.startLine.rfind(' ');
        if (s1 == std::string::npos || s2 == s1) break;
        std::string method = req.startLine.substr(0, s1);
        std::string target = req.startLine.substr(s1 + 1, s2 - s1 - 1);

        if (!tls && method == "CONNECT") {           // HTTPS 터널 요청 -> 여기서 갈라진다
            handleConnect(client, cr, flow, target);
            return;
        }

        std::string host = up.host, path = target;
        uint16_t port = up.port;
        if (!tls) {
            if (target.rfind("http://", 0) != 0) break;
            size_t slash = target.find('/', 7);
            std::string authority = target.substr(7, slash == std::string::npos ? std::string::npos : slash - 7);
            path = slash == std::string::npos ? "/" : target.substr(slash);
            host = authority;
            port = 80;
            size_t colon = authority.rfind(':');
            if (colon != std::string::npos) {
                host = authority.substr(0, colon);
                port = uint16_t(std::stoi(authority.substr(colon + 1)));
            }
            if ((up.sock == BAD_SOCK || host != up.host || port != up.port) && !up.connectPlain(host, port)) {
                cw.write("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                flow.method = method; flow.host = host; flow.port = port; flow.path = path;
                flow.error = "upstream connect failed";
                saveFlow(flow);
                break;
            }
        } else if (target.empty() || target[0] != '/') {
            break;                                   // TLS 안쪽은 origin-form 이어야 함
        }
        flow.method = method;
        flow.scheme = tls ? "https" : "http";
        flow.host = host;
        flow.port = port;
        flow.path = path;
        flow.tls = tlsVersion;
        flow.endpoints = {lab::endpointOf(client, true) + " | " + lab::endpointOf(client, false),
                          lab::endpointOf(up.sock, false) + " | " + lab::endpointOf(up.sock, true)};

        Head out = req;
        out.startLine = method + " " + path + " HTTP/1.1";
        headerErase(out.headers, "Proxy-Connection");
        up.io->write(serialize(out));
        bool ok = true;
        std::string cl = headerGet(req.headers, "Content-Length");
        if (lower(headerGet(req.headers, "Transfer-Encoding")) == "chunked") ok = forwardChunked(cr, *up.io, flow.request, nullptr);
        else if (!cl.empty()) ok = forwardExact(cr, *up.io, std::stoull(cl), flow.request);
        flow.mark("request.end");

        Head res;
        if (!ok || !readHead(up.reader, res)) {
            flow.error = "request relay or response head failed";
            saveFlow(flow);
            break;
        }
        flow.mark("response.headers");
        flow.responseHeaders = res.headers;
        cw.write(serialize(res));
        flow.status = std::atoi(res.startLine.c_str() + res.startLine.find(' ') + 1);

        bool closeAfter = false;
        std::string rcl = headerGet(res.headers, "Content-Length");
        if (method == "HEAD" || flow.status == 204 || flow.status == 304) {
        } else if (lower(headerGet(res.headers, "Transfer-Encoding")) == "chunked") {
            ok = forwardChunked(up.reader, cw, flow.response, &flow.responseTrailers);
        } else if (!rcl.empty()) {
            ok = forwardExact(up.reader, cw, std::stoull(rcl), flow.response);
        } else {
            forwardUntilClose(up.reader, cw, flow.response);
            closeAfter = true;
        }
        if (!ok) flow.error = "response body ended early";
        flow.mark("response.end");
        saveFlow(flow);
        printf("[v2] #%llu %s %s://%s:%u%s -> %d   req %llu B  res %llu B\n", (unsigned long long)flow.id, method.c_str(), flow.scheme.c_str(),
               host.c_str(), port, path.c_str(), flow.status, (unsigned long long)flow.request.total, (unsigned long long)flow.response.total);
        if (!ok || closeAfter || lower(headerGet(req.headers, "Connection")) == "close") break;
    }
}


// ------------------------------------------------------------
// CONNECT 처리: passthrough(단계 1) 또는 MITM(단계 2)
// ------------------------------------------------------------
static void handleConnect(sock_t client, Reader& cr, Flow& flow, const std::string& target) {
    size_t c = target.rfind(':');
    flow.method = "CONNECT";
    flow.host = c == std::string::npos ? target : target.substr(0, c);
    flow.port = c == std::string::npos ? 443 : uint16_t(std::stoi(target.substr(c + 1)));
    flow.path = target;

    sock_t up = lab::connectTo(flow.host, flow.port);
    if (up == BAD_SOCK) {
        lab::sendAll(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
        flow.error = "upstream connect failed";
        saveFlow(flow);
        return;
    }
    flow.endpoints = {lab::endpointOf(client, true) + " | " + lab::endpointOf(client, false),
                      lab::endpointOf(up, false) + " | " + lab::endpointOf(up, true)};
    lab::sendAll(client, "HTTP/1.1 200 Connection Established\r\n\r\n");
    flow.status = 200;
    flow.mark("tunnel.open");

    if (!g_mitm) {
        // ---- 단계 1: passthrough ----
        tunnel(client, cr.buf, up, flow);
        flow.mark("tunnel.close");
        flow.observed = {{"client", describeTls(flow.request.bytes)}, {"server", describeTls(flow.response.bytes)}};
        saveFlow(flow);
        const json& hello = flow.observed["client"];
        std::string sni = hello.is_object() ? hello.value("sni", std::string("?")) : "?";
        printf("[v2] #%llu CONNECT %s  (sni=%s)  client->server %llu B  server->client %llu B\n", (unsigned long long)flow.id,
               target.c_str(), sni.c_str(), (unsigned long long)flow.request.total, (unsigned long long)flow.response.total);
        lab::closeSock(up);
        return;
    }

    // ---- 단계 2: MITM ----
    if (!cr.buf.empty()) {
        flow.error = "client sent TLS bytes together with CONNECT (pre-read); not supported in v2";
        saveFlow(flow);
        lab::closeSock(up);
        return;
    }
    // 세션1: 클라이언트 쪽. 나는 '서버' 역할 -> SSL_accept
    SSL* cs = SSL_new(leafFor(flow.host));
    SSL_set_fd(cs, int(client));
    if (SSL_accept(cs) != 1) {
        flow.error = "client TLS handshake failed: " + tlsError();   // 보통 클라가 CA 를 안 믿을 때
        saveFlow(flow);
        SSL_free(cs);
        lab::closeSock(up);
        printf("[v2] #%llu %s\n", (unsigned long long)flow.id, flow.error.c_str());
        return;
    }
    // 함정 (Windows CI 에서 실제로 걸림): 클라이언트에 따라 인증서 거부가 SSL_accept '이후'에 온다.
    //   (러너의 curl 8.23 / LibreSSL 4.3 로 CA 없이 접속: SSL_accept 는 성공했고 오류는 아무것도 기록되지 않았다)
    //   그러면 위의 handshake 실패 경로를 안 타고, 요청 없이 끊긴 '정상' 터널처럼 보인다.
    //   -> 요청을 기다리기 전에 SSL_peek 로 한 바이트 엿봐서, 실패하면 그 이유(OpenSSL 에러)를 남긴다.
    char firstByte = 0;
    if (SSL_peek(cs, &firstByte, 1) <= 0) {
        flow.error = ERR_peek_error() ? "client ended TLS right after the handshake: " + tlsError() : "client closed TLS before sending a request";
        saveFlow(flow);
        SSL_free(cs);
        lab::closeSock(up);
        printf("[v2] #%llu %s\n", (unsigned long long)flow.id, flow.error.c_str());
        return;
    }
    // 세션2: 서버 쪽. 나는 '클라' 역할 -> SSL_connect + 서버 인증서/호스트명 검증
    Upstream u;
    u.sock = up;
    u.host = flow.host;
    u.port = flow.port;
    u.ssl = SSL_new(g_certs.upstreamCtx);
    SSL_set_fd(u.ssl, int(up));
    SSL_set_tlsext_host_name(u.ssl, flow.host.c_str());                  // 서버에게 보내는 SNI
    unsigned char ip[16];
    if (inet_pton(AF_INET, flow.host.c_str(), ip) == 1 || inet_pton(AF_INET6, flow.host.c_str(), ip) == 1)
        X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(u.ssl), flow.host.c_str());
    else
        SSL_set1_host(u.ssl, flow.host.c_str());                           // 인증서 SAN 이 이 host 인지 검사
    static const unsigned char h11[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    SSL_set_alpn_protos(u.ssl, h11, sizeof(h11));
    if (SSL_connect(u.ssl) != 1) {
        flow.error = "upstream TLS verification failed: " + tlsError();
        saveFlow(flow);
        SSL_free(cs);
        printf("[v2] #%llu %s\n", (unsigned long long)flow.id, flow.error.c_str());
        return;                                                            // u 소멸자가 소켓/SSL 정리
    }
    u.io = std::make_unique<TlsStream>(u.ssl);
    u.reader = Reader{u.io.get(), {}};

    const unsigned char* alpn = nullptr;
    unsigned alpnLen = 0;
    SSL_get0_alpn_selected(cs, &alpn, &alpnLen);
    flow.tls = SSL_get_version(cs);
    flow.observed = {{"mitm", true}, {"clientTls", SSL_get_version(cs)}, {"clientCipher", SSL_get_cipher(cs)},
                     {"clientAlpn", std::string(reinterpret_cast<const char*>(alpn ? alpn : reinterpret_cast<const unsigned char*>("")), alpnLen)},
                     {"upstreamTls", SSL_get_version(u.ssl)}, {"upstreamCipher", SSL_get_cipher(u.ssl)}};
    flow.mark("tls.established");
    saveFlow(flow);                                                        // CONNECT 자체도 한 줄
    printf("[v2] #%llu CONNECT %s  TLS 종단 (client %s / upstream %s)\n", (unsigned long long)flow.id, target.c_str(),
           SSL_get_version(cs), SSL_get_version(u.ssl));

    // ★ 여기부터 평문. v1 의 HTTP 루프를 TLS Stream 위에서 그대로 돌린다.
    TlsStream cio(cs);
    Reader tr{&cio, {}};
    httpLoop(client, tr, cio, u, true, flow.tls);
    SSL_shutdown(cs);
    SSL_free(cs);
}


static void handleClient(sock_t client) {
    lab::setTimeout(client, 30);
    PlainStream cio(client);
    Reader cr{&cio, {}};
    Upstream up;
    httpLoop(client, cr, cio, up, false, "");
    lab::closeSock(client);
}


int main(int argc, char** argv) {
    lab::lineBufferedStdout();
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--mitm") g_mitm = true;
        else g_outPath = a;
    }
    lab::netInit();
    std::string caPath = g_outPath + ".ca.pem";
    if (g_mitm && !makeCa(caPath)) {
        printf("CA 파일을 쓸 수 없음: %s\n", caPath.c_str());
        return 1;
    }
    sock_t listener = lab::listenLocal(LISTEN_PORT);
    if (listener == BAD_SOCK) {
        printf("listen 실패 (포트 %u 사용 중?)\n", LISTEN_PORT);
        return 1;
    }
    printf("[v2] 127.0.0.1:%u 대기, 모드=%s, 기록 -> %s\n", LISTEN_PORT, g_mitm ? "MITM" : "passthrough", g_outPath.c_str());
    if (g_mitm) printf("     CA 인증서: %s   예) curl -x http://127.0.0.1:%u --cacert %s https://example.com/\n", caPath.c_str(), LISTEN_PORT, caPath.c_str());
    for (;;) {
        sock_t c = accept(listener, nullptr, nullptr);
        if (c == BAD_SOCK) continue;
        std::thread(handleClient, c).detach();
    }
}
