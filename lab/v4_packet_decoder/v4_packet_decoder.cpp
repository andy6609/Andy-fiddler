/*
============================================================
 v4_packet_decoder  —  패킷 한 개를 '세포 단위'로 뜯어보기
============================================================
 목적: v1~v3 은 프록시 안에서 본 것(요청/응답)이었다.
       같은 통신을 '선(wire) 위'에서 보면 어떻게 생겼나? -> 패킷.
       Wireshark 가 해주는 걸 직접 짜 보면서, 바이트 하나하나가 어느 층의 무슨 필드인지 확인한다.

 계층 (바깥 -> 안쪽). 각 층의 헤더가 '다음 층이 뭔지' 알려준다:
   Ethernet  [dst MAC 6][src MAC 6][EtherType 2]          EtherType 0x0800=IPv4, 0x86DD=IPv6, 0x0806=ARP
   IPv4      [ver/IHL][TOS][total len][id][flags/frag][TTL][protocol][checksum][src 4][dst 4]
   IPv6      [ver/class/flow 4][payload len 2][next header 1][hop limit 1][src 16][dst 16]
   TCP       [src port][dst port][seq 4][ack 4][offset/flags][window][checksum][urg] (+옵션)
   UDP       [src port][dst port][length][checksum]
   payload   여기서부터가 HTTP / TLS / DNS ... (앱 데이터)

 숫자는 전부 big-endian(network byte order). 0x01BB = 443.
 (TCP_toy 에서 htons() 로 바꿔 보냈던 바로 그 순서)

 [v4 단계 1]  classic pcap + Ethernet/IPv4/TCP/UDP + 목록
 [v4 단계 2]
   + pcapng (요즘 Wireshark 기본 저장 형식) — 블록 구조, 인터페이스별 link type/시간 단위
   + IPv6 (확장 헤더 체인 따라가기), DNS 질의 이름(압축 포인터 루프 방어), TLS 레코드 헤더
   + 모든 필드에 (offset, length) 를 붙인다  <- ★ WireScope 의 "필드 hover -> 바이트 강조" 의 원형
   + 상세 모드: 필드 표 + 계층별 색 hexdump, --field 로 특정 필드 바이트에 ^^ 표시

     ./v4_packet_decoder capture.pcapng            목록
     ./v4_packet_decoder capture.pcapng 3          3번 패킷 상세
     ./v4_packet_decoder capture.pcapng 3 --field "TCP flags"
============================================================
*/

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iterator>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _WIN32
#include <io.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h>
#endif

struct Packet {
    int64_t timeUs = 0;        // 마이크로초
    uint32_t origLen = 0;      // 선 위의 원래 길이
    int linkType = 1;          // 1 = Ethernet, 0/108 = loopback(BSD), 101 = raw IP
    std::string raw;           // 저장된 바이트 (caplen)
};

static uint32_t rd32(const std::string& s, size_t p, bool le) {
    if (p + 4 > s.size()) throw std::runtime_error("파일 잘림");
    auto b = [&](size_t i) { return uint32_t(uint8_t(s[p + i])); };
    return le ? b(0) | b(1) << 8 | b(2) << 16 | b(3) << 24 : b(0) << 24 | b(1) << 16 | b(2) << 8 | b(3);
}
static uint16_t rd16(const std::string& s, size_t p, bool le) {
    if (p + 2 > s.size()) throw std::runtime_error("파일 잘림");
    return le ? uint16_t(uint8_t(s[p]) | uint8_t(s[p + 1]) << 8) : uint16_t(uint8_t(s[p]) << 8 | uint8_t(s[p + 1]));
}
static uint16_t be16(const std::string& s, size_t p) { return uint16_t((uint8_t(s[p]) << 8) | uint8_t(s[p + 1])); }
static uint32_t be32(const std::string& s, size_t p) { return rd32(s, p, false); }


// ------------------------------------------------------------
// 파일 읽기: classic pcap (단계 1) + pcapng (단계 2)
// ------------------------------------------------------------
static void readPcap(const std::string& file, std::vector<Packet>& out) {
    uint32_t magicLE = rd32(file, 0, true);
    bool le = magicLE == 0xa1b2c3d4 || magicLE == 0xa1b23c4d;
    bool nano = magicLE == 0xa1b23c4d || magicLE == 0x4d3cb2a1;
    int link = int(rd32(file, 20, le) & 0xffff);
    for (size_t p = 24; p + 16 <= file.size();) {
        Packet pk;
        uint32_t sec = rd32(file, p, le), frac = rd32(file, p + 4, le), cap = rd32(file, p + 8, le);
        pk.origLen = rd32(file, p + 12, le);
        if (p + 16 + cap > file.size()) throw std::runtime_error("마지막 레코드가 잘림");
        pk.timeUs = int64_t(sec) * 1000000 + (nano ? frac / 1000 : frac);
        pk.linkType = link;
        pk.raw = file.substr(p + 16, cap);
        out.push_back(std::move(pk));
        p += 16 + cap;
    }
}

// pcapng = '블록'의 나열. 모든 블록이 [type 4][total length 4][body ...][total length 4] 모양.
//   SHB(0x0A0D0D0A) : 섹션 시작. byte-order magic 1A2B3C4D 로 엔디안 결정
//   IDB(1)          : 인터페이스 설명. link type + if_tsresol(시간 단위) 옵션
//   EPB(6)          : 패킷 하나. 어느 인터페이스(IDB 번호)에서 왔는지 + 64bit 시간 + 데이터
//   SPB(3)          : 간단 패킷 (시간 없음)
// 그 외 블록(통계, 이름 해석 등)은 길이만 보고 건너뛴다 -> 이게 pcapng 가 확장 가능한 이유.
static void readPcapng(const std::string& file, std::vector<Packet>& out) {
    struct Iface { int link; double unitUs; };
    std::vector<Iface> ifaces;
    bool le = true;
    for (size_t p = 0; p + 12 <= file.size();) {
        if (rd32(file, p, true) == 0x0a0d0d0a) {              // SHB: 엔디안을 여기서 정한다 (type 값은 회문이라 엔디안 무관)
            le = rd32(file, p + 8, true) == 0x1a2b3c4d;
            ifaces.clear();
        }
        uint32_t type = rd32(file, p, le), len = rd32(file, p + 4, le);
        if (len < 12 || len % 4 || p + len > file.size() || rd32(file, p + len - 4, le) != len) throw std::runtime_error("pcapng 블록 길이 이상");
        if (type == 1) {
            Iface f{rd16(file, p + 8, le), 1.0};               // 기본 시간 단위 = 마이크로초 (10^-6)
            for (size_t o = p + 16; o + 4 <= p + len - 4;) {    // 옵션: [code 2][len 2][value, 4바이트 정렬]
                uint16_t code = rd16(file, o, le), olen = rd16(file, o + 2, le);
                if (code == 0) break;
                if (code == 9 && olen == 1) {                   // if_tsresol: 상위비트 0 이면 10^-n, 1 이면 2^-n 초
                    uint8_t r = uint8_t(file[o + 4]);
                    double unitSec = 1;
                    for (int i = 0; i < (r & 0x7f); i++) unitSec /= (r & 0x80) ? 2 : 10;
                    f.unitUs = unitSec * 1e6;
                }
                o += 4 + ((olen + 3u) & ~3u);
            }
            ifaces.push_back(f);
        } else if (type == 6) {
            uint32_t ifId = rd32(file, p + 8, le);
            if (ifId >= ifaces.size()) throw std::runtime_error("EPB 가 없는 인터페이스를 가리킴");
            uint64_t ts = (uint64_t(rd32(file, p + 12, le)) << 32) | rd32(file, p + 16, le);
            uint32_t cap = rd32(file, p + 20, le);
            if (28 + uint64_t(cap) + 4 > len) throw std::runtime_error("EPB 데이터 잘림");
            Packet pk;
            pk.linkType = ifaces[ifId].link;
            pk.timeUs = int64_t(double(ts) * ifaces[ifId].unitUs);
            pk.origLen = rd32(file, p + 24, le);
            pk.raw = file.substr(p + 28, cap);
            out.push_back(std::move(pk));
        } else if (type == 3 && !ifaces.empty()) {
            Packet pk;
            pk.linkType = ifaces[0].link;
            pk.origLen = rd32(file, p + 8, le);
            pk.raw = file.substr(p + 12, std::min<size_t>(pk.origLen, len - 16));
            out.push_back(std::move(pk));
        }
        p += len;
    }
}

static void readCaptureFile(const std::string& file, std::vector<Packet>& out) {
    if (file.size() < 12) throw std::runtime_error("파일이 너무 짧음");
    uint32_t m = rd32(file, 0, true);
    if (m == 0x0a0d0d0a) readPcapng(file, out);
    else if (m == 0xa1b2c3d4 || m == 0xa1b23c4d || m == 0xd4c3b2a1 || m == 0x4d3cb2a1) readPcap(file, out);
    else throw std::runtime_error("pcap/pcapng 아님");
}


// ------------------------------------------------------------
// 계층 해석 — 모든 필드에 (offset, length) 를 붙인다
// ------------------------------------------------------------
enum Layer { LINK, NET, TRANSPORT, APP, PAYLOAD };
struct Field {
    Layer layer;
    std::string name, value;
    size_t offset, length;
};
struct Decoded {
    std::string proto = "?", src, dst, info, error;
    std::vector<Field> fields;
    size_t netStart = 0, transportStart = 0, payloadStart = 0, end = 0;   // hexdump 색칠용 경계
};

static std::string ipv4(const std::string& s, size_t p) {
    return std::to_string(uint8_t(s[p])) + "." + std::to_string(uint8_t(s[p + 1])) + "." + std::to_string(uint8_t(s[p + 2])) + "." +
           std::to_string(uint8_t(s[p + 3]));
}
static std::string ipv6(const std::string& s, size_t p) {
    char b[48];
    std::string out;
    for (int i = 0; i < 8; i++) {
        snprintf(b, sizeof(b), "%x", be16(s, p + i * 2));
        out += (i ? ":" : "") + std::string(b);
    }
    return out;                                    // (:: 축약은 생략 — 오히려 위치 대응이 보기 쉬움)
}
static std::string hex4(uint16_t v) {
    char b[8];
    snprintf(b, sizeof(b), "0x%04x", v);
    return b;
}

// DNS 이름: [길이][글자...][길이][글자...][0]. 길이 바이트 상위 2비트가 11 이면 '압축 포인터'
// (메시지 앞쪽에 나온 이름을 가리킴). 악의적 패킷은 포인터가 자기 자신을 가리켜 무한루프를 만든다 -> 방문 기록으로 막음.
static std::string dnsName(const std::string& s, size_t msgStart, size_t end, size_t& pos) {
    std::string name;
    size_t p = pos;
    bool jumped = false;
    std::set<size_t> seen;
    for (int guard = 0; guard < 128; guard++) {
        if (p >= end || !seen.insert(p).second) throw std::runtime_error("DNS 이름 범위 밖/포인터 루프");
        uint8_t len = uint8_t(s[p++]);
        if (len == 0) { if (!jumped) pos = p; return name; }
        if ((len & 0xc0) == 0xc0) {
            if (p >= end) break;
            size_t target = msgStart + (size_t(len & 0x3f) << 8 | uint8_t(s[p++]));
            if (!jumped) pos = p;
            jumped = true;
            p = target;
            continue;
        }
        if (len > 63 || p + len > end) break;
        name += (name.empty() ? "" : ".") + s.substr(p, len);
        p += len;
    }
    throw std::runtime_error("DNS 이름 형식 이상");
}

static Decoded decode(const Packet& pk) {
    Decoded d;
    const std::string& s = pk.raw;
    size_t end = s.size(), off = 0;
    auto field = [&](Layer l, std::string n, std::string v, size_t o, size_t len) { d.fields.push_back({l, std::move(n), std::move(v), o, len}); };
    try {
        uint16_t etherType = 0;
        if (pk.linkType == 1) {                                     // Ethernet
            if (end < 14) throw std::runtime_error("Ethernet 헤더 잘림");
            etherType = be16(s, 12);
            field(LINK, "Ethernet type", hex4(etherType), 12, 2);
            off = 14;
            if (etherType == 0x8100) {                              // 802.1Q VLAN 태그가 끼어 있으면 4바이트 건너뜀
                if (end < 18) throw std::runtime_error("VLAN 태그 잘림");
                field(LINK, "VLAN id", std::to_string(be16(s, 14) & 0x0fff), 14, 2);
                etherType = be16(s, 16);
                field(LINK, "Ethernet type (inner)", hex4(etherType), 16, 2);
                off = 18;
            }
        } else if (pk.linkType == 0 || pk.linkType == 108) {       // BSD loopback (macOS lo0): 4바이트 address family
            if (end < 5) throw std::runtime_error("loopback 헤더 잘림");
            off = 4;
            etherType = (uint8_t(s[4]) >> 4) == 6 ? 0x86dd : 0x0800;
        } else if (pk.linkType == 101 || pk.linkType == 12) {      // raw IP
            etherType = (end && (uint8_t(s[0]) >> 4) == 6) ? 0x86dd : 0x0800;
        } else {
            d.info = "link type " + std::to_string(pk.linkType);
            return d;
        }
        d.netStart = off;
        if (etherType == 0x0806) { d.proto = "ARP"; d.transportStart = d.payloadStart = d.end = end; return d; }

        uint8_t proto = 0;
        if (etherType == 0x0800) {
            if (off + 20 > end) throw std::runtime_error("IPv4 헤더 잘림");
            size_t ihl = (uint8_t(s[off]) & 0x0f) * 4;
            uint16_t total = be16(s, off + 2);
            if (ihl < 20 || off + ihl > end || total < ihl) throw std::runtime_error("IPv4 길이 이상");
            end = std::min(end, off + total);                       // Ethernet padding 제외
            proto = uint8_t(s[off + 9]);
            d.src = ipv4(s, off + 12);
            d.dst = ipv4(s, off + 16);
            field(NET, "IPv4 header length", std::to_string(ihl), off, 1);
            field(NET, "IPv4 total length", std::to_string(total), off + 2, 2);
            field(NET, "IPv4 TTL", std::to_string(uint8_t(s[off + 8])), off + 8, 1);
            field(NET, "IPv4 protocol", std::to_string(proto), off + 9, 1);
            field(NET, "IPv4 source", d.src, off + 12, 4);
            field(NET, "IPv4 destination", d.dst, off + 16, 4);
            if (be16(s, off + 6) & 0x3fff) { d.proto = "IP frag"; d.info = "조각난 IP 패킷 (재조립은 범위 밖)"; d.transportStart = d.payloadStart = d.end = end; return d; }
            off += ihl;
        } else if (etherType == 0x86dd) {
            if (off + 40 > end) throw std::runtime_error("IPv6 헤더 잘림");
            proto = uint8_t(s[off + 6]);
            d.src = ipv6(s, off + 8);
            d.dst = ipv6(s, off + 24);
            end = std::min(end, off + 40 + be16(s, off + 4));
            field(NET, "IPv6 payload length", std::to_string(be16(s, off + 4)), off + 4, 2);
            field(NET, "IPv6 next header", std::to_string(proto), off + 6, 1);
            field(NET, "IPv6 hop limit", std::to_string(uint8_t(s[off + 7])), off + 7, 1);
            field(NET, "IPv6 source", d.src, off + 8, 16);
            field(NET, "IPv6 destination", d.dst, off + 24, 16);
            off += 40;
            d.src = "[" + d.src + "]";                              // IPv6 에 포트를 붙일 땐 대괄호 (안 그러면 마지막 ':' 가 헷갈림)
            d.dst = "[" + d.dst + "]";
            // 확장 헤더 체인: hop-by-hop(0), routing(43), dest options(60), fragment(44)
            for (int i = 0; i < 8 && (proto == 0 || proto == 43 || proto == 60 || proto == 44); i++) {
                if (off + 8 > end) throw std::runtime_error("IPv6 확장 헤더 잘림");
                size_t len = proto == 44 ? 8 : (size_t(uint8_t(s[off + 1])) + 1) * 8;
                field(NET, "IPv6 extension " + std::to_string(proto), std::to_string(len) + " bytes", off, len);
                proto = uint8_t(s[off]);
                off += len;
            }
        } else {
            d.proto = "Ether";
            d.info = "EtherType " + hex4(etherType);
            return d;
        }
        d.transportStart = off;
        d.end = end;

        size_t payload = off;
        if (proto == 6) {
            if (off + 20 > end) throw std::runtime_error("TCP 헤더 잘림");
            size_t thl = (uint8_t(s[off + 12]) >> 4) * 4;
            if (thl < 20 || off + thl > end) throw std::runtime_error("TCP 헤더 길이 이상");
            uint8_t flags = uint8_t(s[off + 13]);
            std::string f;
            for (auto [bit, name] : {std::pair{0x02, "SYN"}, {0x10, "ACK"}, {0x01, "FIN"}, {0x04, "RST"}, {0x08, "PSH"}, {0x20, "URG"}})
                if (flags & bit) f += f.empty() ? name : std::string(" ") + name;
            d.proto = "TCP";
            field(TRANSPORT, "TCP source port", std::to_string(be16(s, off)), off, 2);
            field(TRANSPORT, "TCP destination port", std::to_string(be16(s, off + 2)), off + 2, 2);
            field(TRANSPORT, "TCP sequence", std::to_string(be32(s, off + 4)), off + 4, 4);
            field(TRANSPORT, "TCP acknowledgment", std::to_string(be32(s, off + 8)), off + 8, 4);
            field(TRANSPORT, "TCP header length", std::to_string(thl), off + 12, 1);
            field(TRANSPORT, "TCP flags", f, off + 13, 1);
            field(TRANSPORT, "TCP window", std::to_string(be16(s, off + 14)), off + 14, 2);
            d.src += ":" + std::to_string(be16(s, off));
            d.dst += ":" + std::to_string(be16(s, off + 2));
            payload = off + thl;
            d.info = "[" + f + "] seq=" + std::to_string(be32(s, off + 4)) + " ack=" + std::to_string(be32(s, off + 8));
        } else if (proto == 17) {
            if (off + 8 > end) throw std::runtime_error("UDP 헤더 잘림");
            d.proto = "UDP";
            field(TRANSPORT, "UDP source port", std::to_string(be16(s, off)), off, 2);
            field(TRANSPORT, "UDP destination port", std::to_string(be16(s, off + 2)), off + 2, 2);
            field(TRANSPORT, "UDP length", std::to_string(be16(s, off + 4)), off + 4, 2);
            d.src += ":" + std::to_string(be16(s, off));
            d.dst += ":" + std::to_string(be16(s, off + 2));
            payload = off + 8;
        } else {
            d.proto = proto == 1 ? "ICMP" : proto == 58 ? "ICMPv6" : "IP/" + std::to_string(proto);
            d.payloadStart = off;
            return d;
        }
        d.payloadStart = payload;
        size_t plen = payload <= end ? end - payload : 0;
        if (plen) field(PAYLOAD, "Payload", std::to_string(plen) + " bytes", payload, plen);

        // ---- 앱 계층: 포트/첫 바이트로 '무엇처럼 생겼는지'만 본다 (확신이 아니라 모양) ----
        uint16_t sp = be16(s, d.transportStart), dp = be16(s, d.transportStart + 2);
        if (proto == 17 && (sp == 53 || dp == 53) && plen >= 12) {
            d.proto = "DNS";
            uint16_t flags = be16(s, payload + 2);
            field(APP, "DNS id", std::to_string(be16(s, payload)), payload, 2);
            field(APP, "DNS flags", std::string(flags & 0x8000 ? "response" : "query"), payload + 2, 2);
            size_t q = payload + 12;
            if (be16(s, payload + 4)) {
                std::string name = dnsName(s, payload, end, q);
                field(APP, "DNS question", name, payload + 12, q - payload - 12);
                d.info = std::string(flags & 0x8000 ? "response " : "query ") + name;
            }
        } else if (proto == 6 && plen >= 5 && uint8_t(s[payload]) >= 20 && uint8_t(s[payload]) <= 23 && uint8_t(s[payload + 1]) == 3) {
            static const char* rec[] = {"ChangeCipherSpec", "Alert", "Handshake", "ApplicationData"};
            d.proto = "TLS";
            field(APP, "TLS record type", rec[uint8_t(s[payload]) - 20], payload, 1);
            field(APP, "TLS record version", std::to_string(be16(s, payload + 1)), payload + 1, 2);
            field(APP, "TLS record length", std::to_string(be16(s, payload + 3)), payload + 3, 2);
            d.info += std::string("  ") + rec[uint8_t(s[payload]) - 20];
        } else if (proto == 6 && plen) {
            std::string head = s.substr(payload, std::min<size_t>(plen, 8));
            for (const char* m : {"GET ", "POST ", "PUT ", "HTTP/", "CONNECT "})
                if (head.rfind(m, 0) == 0) {
                    d.proto = "HTTP";
                    size_t eol = s.find("\r\n", payload);
                    d.info = s.substr(payload, std::min(eol == std::string::npos ? end : eol, end) - payload);
                }
        }
    } catch (const std::exception& e) {
        d.error = e.what();                 // 어디까지 해석했는지는 fields 에 남아 있다
    }
    return d;
}


// ------------------------------------------------------------
// 출력
// ------------------------------------------------------------
static std::string fmtTime(int64_t us) {
    time_t sec = time_t(us / 1000000);
    char b[32];
    strftime(b, sizeof(b), "%H:%M:%S", localtime(&sec));
    char out[48];
    snprintf(out, sizeof(out), "%s.%06lld", b, (long long)(us % 1000000));
    return out;
}

static void printList(const std::vector<Packet>& packets) {
    printf("%-4s %-16s %-24s %-24s %-6s %-5s %s\n", "#", "time", "source", "destination", "proto", "len", "info");
    for (size_t i = 0; i < packets.size(); i++) {
        Decoded d = decode(packets[i]);
        printf("%-4zu %-16s %-24s %-24s %-6s %-5u %s%s\n", i + 1, fmtTime(packets[i].timeUs).c_str(), d.src.c_str(), d.dst.c_str(),
               d.proto.c_str(), packets[i].origLen, d.info.c_str(), d.error.empty() ? "" : ("  !! " + d.error).c_str());
    }
}

// 상세: 필드 표 + hexdump. 바이트 색 = 계층 (터미널일 때만), --field 로 고른 필드는 아래 줄에 ^^
static void printDetail(const Packet& pk, size_t index, const std::string& pick) {
    Decoded d = decode(pk);
    bool color = isatty(fileno(stdout)) && !getenv("NO_COLOR");
    const char* LAYER_COLOR[] = {"\033[34m", "\033[32m", "\033[33m", "\033[36m", "\033[35m"};
    const char* LAYER_NAME[] = {"link", "network", "transport", "app", "payload"};
    printf("packet #%zu  %s  link type %d  %zu of %u bytes captured\n", index, fmtTime(pk.timeUs).c_str(), pk.linkType, pk.raw.size(), pk.origLen);
    if (!d.error.empty()) printf("!! 해석 중단: %s\n", d.error.c_str());
    printf("\n%-10s %-26s %-28s %7s %7s\n", "layer", "field", "value", "offset", "length");
    size_t hiFrom = 0, hiTo = 0;
    for (auto& f : d.fields) {
        printf("%-10s %-26s %-28s %7zu %7zu\n", LAYER_NAME[f.layer], f.name.c_str(), f.value.substr(0, 28).c_str(), f.offset, f.length);
        if (!pick.empty() && f.name == pick) { hiFrom = f.offset; hiTo = f.offset + f.length; }
    }
    auto layerOf = [&](size_t i) -> int {
        if (i >= d.end && d.end) return -1;                 // IP 길이 밖 = Ethernet padding
        if (i >= d.payloadStart && d.payloadStart) return PAYLOAD;
        if (i >= d.transportStart && d.transportStart) return TRANSPORT;
        if (i >= d.netStart && d.netStart) return NET;
        return LINK;
    };
    printf("\n");
    for (size_t row = 0; row < pk.raw.size(); row += 16) {
        std::string marks;
        printf("%06zx  ", row);
        for (size_t i = row; i < row + 16; i++) {
            if (i >= pk.raw.size()) { printf("   "); continue; }
            int l = layerOf(i);
            if (color) printf("%s", l < 0 ? "\033[2m" : LAYER_COLOR[l]);
            printf("%02x ", uint8_t(pk.raw[i]));
            if (color) printf("\033[0m");
            marks += (i >= hiFrom && i < hiTo) ? "^^ " : "   ";
        }
        printf(" ");
        for (size_t i = row; i < row + 16 && i < pk.raw.size(); i++) {
            unsigned char c = uint8_t(pk.raw[i]);
            putchar(c >= 32 && c < 127 ? c : '.');
        }
        printf("\n");
        if (hiTo > hiFrom && marks.find('^') != std::string::npos) printf("        %s\n", marks.c_str());
    }
    if (color) printf("\n색: \033[34mlink\033[0m \033[32mnetwork\033[0m \033[33mtransport\033[0m \033[35mpayload\033[0m \033[2mpadding\033[0m\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("사용법: %s capture.pcap|pcapng [패킷번호] [--field \"필드 이름\"]\n", argv[0]);
        return 1;
    }
    std::ifstream in(argv[1], std::ios::binary);
    std::string file((std::istreambuf_iterator<char>(in)), {});
    std::vector<Packet> packets;
    try {
        readCaptureFile(file, packets);
    } catch (const std::exception& e) {
        printf("읽기 실패: %s\n", e.what());
        return 1;
    }
    size_t index = 0;
    std::string pick;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--field" && i + 1 < argc) pick = argv[++i];
        else index = size_t(std::strtoul(a.c_str(), nullptr, 10));
    }
    if (!index) printList(packets);
    else if (index <= packets.size()) printDetail(packets[index - 1], index, pick);
    else printf("패킷 %zu 없음 (전체 %zu개)\n", index, packets.size());
    return 0;
}
