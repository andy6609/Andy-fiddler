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
                                                          protocol 6=TCP, 17=UDP, 1=ICMP
   TCP       [src port][dst port][seq 4][ack 4][offset/flags][window][checksum][urg] (+옵션)
   UDP       [src port][dst port][length][checksum]
   payload   여기서부터가 HTTP / TLS / DNS ... (앱 데이터)

 숫자는 전부 big-endian(network byte order). 0x01BB = 443.
 (TCP_toy 에서 htons() 로 바꿔 보냈던 바로 그 순서)

 [v4 단계 1 — 이 커밋]
   classic pcap 파일 읽기 + Ethernet/IPv4/TCP/UDP 해석 + 목록 출력
     ./v4_packet_decoder capture.pcap
     #  time            source               destination          proto  len  info

 pcap 파일 구조 (libpcap 형식, 1998년부터 거의 그대로):
   [global header 24B: magic a1b2c3d4, 버전, snaplen, linktype]
   [record header 16B: ts_sec, ts_usec, caplen, origlen][packet bytes caplen개]  <- 반복
   caplen < origlen 이면 앞부분만 저장된 것 (snaplen 으로 잘림)
============================================================
*/

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

struct Packet {
    int64_t timeUs = 0;        // 마이크로초
    uint32_t origLen = 0;      // 선 위의 원래 길이
    int linkType = 1;          // 1 = Ethernet
    std::string raw;           // 저장된 바이트 (caplen)
};

// little-endian(파일 헤더가 LE 로 쓰인 경우) / big-endian 읽기
static uint32_t rd32(const std::string& s, size_t p, bool le) {
    auto b = [&](size_t i) { return uint32_t(uint8_t(s[p + i])); };
    return le ? b(0) | b(1) << 8 | b(2) << 16 | b(3) << 24 : b(0) << 24 | b(1) << 16 | b(2) << 8 | b(3);
}
static uint16_t be16(const std::string& s, size_t p) { return uint16_t((uint8_t(s[p]) << 8) | uint8_t(s[p + 1])); }
static uint32_t be32(const std::string& s, size_t p) { return rd32(s, p, false); }


// ------------------------------------------------------------
// classic pcap 읽기
//   magic 으로 바이트 순서와 시간 단위를 알아낸다:
//     d4 c3 b2 a1 (파일에 이렇게 써 있음) -> little-endian, 마이크로초
//     4d 3c b2 a1                         -> little-endian, 나노초
//     a1 b2 c3 d4 / a1 b2 3c 4d           -> big-endian
// ------------------------------------------------------------
static bool readPcap(const std::string& file, std::vector<Packet>& out, std::string& err) {
    if (file.size() < 24) { err = "파일이 너무 짧음"; return false; }
    uint32_t magicLE = rd32(file, 0, true);
    bool le, nano;
    if (magicLE == 0xa1b2c3d4) { le = true; nano = false; }
    else if (magicLE == 0xa1b23c4d) { le = true; nano = true; }
    else if (magicLE == 0xd4c3b2a1) { le = false; nano = false; }
    else if (magicLE == 0x4d3cb2a1) { le = false; nano = true; }
    else { err = "pcap magic 아님"; return false; }
    int link = int(rd32(file, 20, le) & 0xffff);
    size_t p = 24;
    while (p + 16 <= file.size()) {
        Packet pk;
        uint32_t sec = rd32(file, p, le), frac = rd32(file, p + 4, le), cap = rd32(file, p + 8, le);
        pk.origLen = rd32(file, p + 12, le);
        if (p + 16 + cap > file.size()) { err = "마지막 레코드가 잘림"; return false; }
        pk.timeUs = int64_t(sec) * 1000000 + (nano ? frac / 1000 : frac);
        pk.linkType = link;
        pk.raw = file.substr(p + 16, cap);
        out.push_back(std::move(pk));
        p += 16 + cap;
    }
    return true;
}


// ------------------------------------------------------------
// 계층 해석
// ------------------------------------------------------------
struct Decoded {
    std::string proto = "?", src, dst, info, error;
};

static std::string ipv4(const std::string& s, size_t p) {
    return std::to_string(uint8_t(s[p])) + "." + std::to_string(uint8_t(s[p + 1])) + "." + std::to_string(uint8_t(s[p + 2])) + "." +
           std::to_string(uint8_t(s[p + 3]));
}

static Decoded decode(const Packet& pk) {
    Decoded d;
    const std::string& s = pk.raw;
    size_t end = s.size();
    if (pk.linkType != 1) { d.info = "link type " + std::to_string(pk.linkType) + " (단계 1은 Ethernet 만)"; return d; }
    if (end < 14) { d.error = "Ethernet 헤더 잘림"; return d; }
    uint16_t etherType = be16(s, 12);
    if (etherType != 0x0800) { d.proto = "Ether"; d.info = "EtherType 0x" + std::to_string(etherType); return d; }

    size_t ip = 14;
    if (ip + 20 > end) { d.error = "IPv4 헤더 잘림"; return d; }
    size_t ihl = (uint8_t(s[ip]) & 0x0f) * 4;              // 하위 4비트 x 4 = IP 헤더 길이 (옵션 있으면 20보다 큼)
    uint16_t totalLen = be16(s, ip + 2);
    if (ihl < 20 || ip + ihl > end) { d.error = "IHL 이상"; return d; }
    end = std::min(end, ip + totalLen);                     // Ethernet 최소 길이(60B) 맞추려는 padding 은 잘라냄
    uint8_t protocol = uint8_t(s[ip + 9]);
    d.src = ipv4(s, ip + 12);
    d.dst = ipv4(s, ip + 16);

    size_t l4 = ip + ihl;
    if (protocol == 6 && l4 + 20 <= end) {
        size_t thl = (uint8_t(s[l4 + 12]) >> 4) * 4;       // data offset: 상위 4비트 x 4
        uint8_t flags = uint8_t(s[l4 + 13]);
        d.proto = "TCP";
        d.src += ":" + std::to_string(be16(s, l4));
        d.dst += ":" + std::to_string(be16(s, l4 + 2));
        std::string f;
        for (auto [bit, name] : {std::pair{0x02, "SYN"}, {0x10, "ACK"}, {0x01, "FIN"}, {0x04, "RST"}, {0x08, "PSH"}})
            if (flags & bit) f += f.empty() ? name : std::string(" ") + name;
        size_t payload = l4 + thl;
        d.info = "[" + f + "] seq=" + std::to_string(be32(s, l4 + 4)) + " ack=" + std::to_string(be32(s, l4 + 8)) +
                 " payload=" + std::to_string(payload <= end ? end - payload : 0);
    } else if (protocol == 17 && l4 + 8 <= end) {
        d.proto = "UDP";
        d.src += ":" + std::to_string(be16(s, l4));
        d.dst += ":" + std::to_string(be16(s, l4 + 2));
        d.info = "len=" + std::to_string(be16(s, l4 + 4) - 8);
    } else {
        d.proto = "IP/" + std::to_string(protocol);
    }
    return d;
}


static std::string clock(int64_t us) {
    time_t sec = time_t(us / 1000000);
    char b[32];
    strftime(b, sizeof(b), "%H:%M:%S", localtime(&sec));
    char out[48];
    snprintf(out, sizeof(out), "%s.%06lld", b, (long long)(us % 1000000));
    return out;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("사용법: %s capture.pcap\n", argv[0]);
        return 1;
    }
    std::ifstream in(argv[1], std::ios::binary);
    std::string file((std::istreambuf_iterator<char>(in)), {});
    std::vector<Packet> packets;
    std::string err;
    if (!readPcap(file, packets, err)) {
        printf("읽기 실패: %s\n", err.c_str());
        return 1;
    }
    printf("%-4s %-16s %-22s %-22s %-6s %-5s %s\n", "#", "time", "source", "destination", "proto", "len", "info");
    for (size_t i = 0; i < packets.size(); i++) {
        Decoded d = decode(packets[i]);
        printf("%-4zu %-16s %-22s %-22s %-6s %-5u %s%s\n", i + 1, clock(packets[i].timeUs).c_str(), d.src.c_str(), d.dst.c_str(), d.proto.c_str(),
               packets[i].origLen, d.info.c_str(), d.error.empty() ? "" : ("  !! " + d.error).c_str());
    }
    return 0;
}
