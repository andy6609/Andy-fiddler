/*
============================================================
 v5_tcp_stream  —  패킷 조각들을 '연결'과 '바이트 흐름'으로 다시 모으기
============================================================
 목적: v4 는 패킷 하나씩 봤다. 그런데 HTTP 요청 하나는 패킷 여러 개에 쪼개져 가고,
       한 패킷에 요청 두 개 일부가 같이 실리기도 한다. TCP 는 '바이트 흐름'만 약속하니까.
       => 같은 연결의 패킷을 모으고, 순서번호(seq)로 줄 세워서 원래 바이트 흐름을 복원한다.

 연결을 구분하는 열쇠 = 4-tuple (src IP, src port, dst IP, dst port)
   A:5000 -> B:80 과 B:80 -> A:5000 은 같은 연결의 두 방향.
   -> 두 끝점을 정렬해서 "작은쪽 | 큰쪽" 으로 key 를 만든다 (WireScope connectionKey() 와 같은 방식).
      v1 이 기록한 endpoints 와 같은 모양이라서, 프록시 Flow 와 패킷을 이 key 로 연결할 수 있다.

 [v5 단계 1]  연결 목록 + 핸드셰이크/종료 관찰
     ./v5_tcp_stream capture.pcap
   연결마다: 패킷 수, 방향별 payload 바이트, 그리고 상태 변화
     SYN -> SYN+ACK -> ACK            (3-way handshake)
     FIN -> ACK / FIN -> ACK          (정상 종료, 양쪽이 각자 FIN)
     RST                              (강제 종료)
   캡처가 연결 '중간부터' 시작했으면 SYN 이 없다 -> "SYN 못 봄" 으로 그대로 표시.

 [v5 단계 2]  한 연결의 바이트 흐름 복원
     ./v5_tcp_stream capture.pcap 1          1번 연결, 텍스트
     ./v5_tcp_stream capture.pcap 1 --hex    hexdump

   방향마다:
     1) 상대 순서번호: rel = seq - (ISN + 1).  SYN 이 1바이트를 '소비'하니까 +1.
        (ISN 은 보안상 랜덤이라 절대값은 의미 없음. Wireshark 도 기본으로 상대값을 보여줌)
     2) payload 있는 세그먼트를 rel 순서로 정렬
     3) 앞에서부터 이어붙이며 '실제 캡처에서 일어난 일'을 그대로 표시:
          - rel > 지금까지 끝  -> GAP (캡처가 놓친 바이트. 지어내서 채우지 않는다)
          - 전부 이미 받은 범위 -> 재전송(retransmission)으로 보고 버림
          - 일부만 겹침         -> 겹친 앞부분은 버리고 뒷부분만
          - 도착 순서가 seq 순서와 다름 -> out of order 표시
   ★ "캡처가 놓친 것"(GAP) 과 "네트워크에서 실제로 잃어버린 것" 은 다르다.
      TCP 는 잃어버리면 재전송하니까, 받는 쪽 앱은 결국 다 받는다. GAP 은 '우리 캡처'의 구멍.

 한계: 순서번호 wrap(2^32) 은 차이 계산(int32)으로만 처리, SACK/window/zero-window 해석 안 함,
       연결 재사용(같은 4-tuple 로 FIN 후 새 SYN) 을 별도 연결로 나누지 않음.
       WireScope 본체 streamPreview() 도 같은 수준이며 화면에 "full reassembly 아님" 이라고 적어 둠.
============================================================
*/

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#endif

// ------------------------------------------------------------
// 파일 읽기 + TCP 까지만 해석 (v4 에서 필요한 부분만 가져옴)
// ------------------------------------------------------------
struct Packet {
    int64_t timeUs = 0;
    int linkType = 1;
    std::string raw;
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
static uint16_t be16(const std::string& s, size_t p) { return rd16(s, p, false); }
static uint32_t be32(const std::string& s, size_t p) { return rd32(s, p, false); }

static std::vector<Packet> readCaptureFile(const std::string& f) {
    std::vector<Packet> out;
    uint32_t m = rd32(f, 0, true);
    if (m == 0x0a0d0d0a) {                                     // pcapng
        std::vector<std::pair<int, double>> ifs;
        bool le = true;
        for (size_t p = 0; p + 12 <= f.size();) {
            if (rd32(f, p, true) == 0x0a0d0d0a) { le = rd32(f, p + 8, true) == 0x1a2b3c4d; ifs.clear(); }
            uint32_t type = rd32(f, p, le), len = rd32(f, p + 4, le);
            if (len < 12 || p + len > f.size()) throw std::runtime_error("pcapng 블록 이상");
            if (type == 1) ifs.push_back({rd16(f, p + 8, le), 1.0});
            if (type == 6 && rd32(f, p + 8, le) < ifs.size()) {
                auto& itf = ifs[rd32(f, p + 8, le)];
                uint64_t ts = (uint64_t(rd32(f, p + 12, le)) << 32) | rd32(f, p + 16, le);
                out.push_back({int64_t(double(ts) * itf.second), itf.first, f.substr(p + 28, rd32(f, p + 20, le))});
            }
            p += len;
        }
    } else if (m == 0xa1b2c3d4 || m == 0xd4c3b2a1) {           // classic pcap (마이크로초)
        bool le = m == 0xa1b2c3d4;
        int link = int(rd32(f, 20, le) & 0xffff);
        for (size_t p = 24; p + 16 <= f.size();) {
            uint32_t cap = rd32(f, p + 8, le);
            if (p + 16 + cap > f.size()) throw std::runtime_error("레코드 잘림");
            out.push_back({int64_t(rd32(f, p, le)) * 1000000 + rd32(f, p + 4, le), link, f.substr(p + 16, cap)});
            p += 16 + cap;
        }
    } else {
        throw std::runtime_error("pcap/pcapng 아님");
    }
    return out;
}

struct Segment {
    size_t packet;            // 1부터 (v4 번호와 같음)
    int64_t timeUs;
    std::string src, dst;     // "IP:port" (IPv6 는 [IP]:port)
    uint32_t seq, ack;
    uint8_t flags;
    std::string payload;
};

static std::string ipStr(const std::string& s, size_t p, bool v6) {
    char b[64];
    if (!v6) { snprintf(b, sizeof(b), "%u.%u.%u.%u", uint8_t(s[p]), uint8_t(s[p + 1]), uint8_t(s[p + 2]), uint8_t(s[p + 3])); return b; }
    std::string o = "[";
    for (int i = 0; i < 8; i++) { snprintf(b, sizeof(b), "%s%x", i ? ":" : "", be16(s, p + i * 2)); o += b; }
    return o + "]";
}

// TCP 가 아니거나 해석이 안 되면 false
static bool toSegment(const Packet& pk, size_t index, Segment& seg) {
    const std::string& s = pk.raw;
    size_t off, end = s.size();
    uint16_t et;
    if (pk.linkType == 1) { if (end < 14) return false; et = be16(s, 12); off = 14; }
    else if (pk.linkType == 0 || pk.linkType == 108) { if (end < 5) return false; off = 4; et = (uint8_t(s[4]) >> 4) == 6 ? 0x86dd : 0x800; }
    else return false;
    bool v6 = et == 0x86dd;
    if (et == 0x0800) {
        if (off + 20 > end || uint8_t(s[off + 9]) != 6) return false;
        size_t ihl = (uint8_t(s[off]) & 15) * 4;
        end = std::min(end, off + be16(s, off + 2));
        seg.src = ipStr(s, off + 12, false);
        seg.dst = ipStr(s, off + 16, false);
        off += ihl;
    } else if (v6) {
        if (off + 40 > end || uint8_t(s[off + 6]) != 6) return false;   // (확장 헤더가 끼면 v5 에선 건너뜀)
        end = std::min(end, off + 40 + be16(s, off + 4));
        seg.src = ipStr(s, off + 8, true);
        seg.dst = ipStr(s, off + 24, true);
        off += 40;
    } else {
        return false;
    }
    if (off + 20 > end) return false;
    size_t thl = (uint8_t(s[off + 12]) >> 4) * 4;
    if (thl < 20 || off + thl > end) return false;
    seg.packet = index;
    seg.timeUs = pk.timeUs;
    seg.src += ":" + std::to_string(be16(s, off));
    seg.dst += ":" + std::to_string(be16(s, off + 2));
    seg.seq = be32(s, off + 4);
    seg.ack = be32(s, off + 8);
    seg.flags = uint8_t(s[off + 13]);
    seg.payload = s.substr(off + thl, end - off - thl);
    return true;
}


// ------------------------------------------------------------
// 연결로 묶기
// ------------------------------------------------------------
enum { FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10 };

static std::string flagStr(uint8_t f) {
    std::string o;
    for (auto [bit, n] : {std::pair{SYN, "SYN"}, {FIN, "FIN"}, {RST, "RST"}, {ACK, "ACK"}, {PSH, "PSH"}})   // 흔히 쓰는 표기 순서: SYN+ACK, FIN+ACK
        if (f & bit) o += o.empty() ? n : std::string("+") + n;
    return o;
}

struct Connection {
    std::string key, client, server;     // client = 처음 SYN 보낸 쪽 (못 봤으면 첫 패킷 보낸 쪽)
    std::vector<Segment> segs;
    bool sawSyn = false;
};

static std::string connKey(std::string a, std::string b) {
    if (a > b) std::swap(a, b);
    return a + " | " + b;
}

static std::vector<Connection> group(const std::vector<Segment>& segs) {
    std::map<std::string, size_t> index;
    std::vector<Connection> conns;
    for (auto& s : segs) {
        std::string k = connKey(s.src, s.dst);
        auto it = index.find(k);
        if (it == index.end()) {
            it = index.emplace(k, conns.size()).first;
            conns.push_back({k, s.src, s.dst, {}, false});
        }
        Connection& c = conns[it->second];
        if ((s.flags & SYN) && !(s.flags & ACK) && !c.sawSyn) {   // 순수 SYN 을 보낸 쪽 = 클라이언트
            c.sawSyn = true;
            c.client = s.src;
            c.server = s.dst;
        }
        c.segs.push_back(s);
    }
    return conns;
}

// 핸드셰이크/종료 이벤트만 시간순으로
static void printLifecycle(const Connection& c) {
    int64_t t0 = c.segs.front().timeUs;
    for (auto& s : c.segs) {
        if (!(s.flags & (SYN | FIN | RST))) continue;
        printf("      +%8.3f ms  #%-4zu %s  %-11s seq=%u ack=%u\n", double(s.timeUs - t0) / 1000.0, s.packet,
               s.src == c.client ? "C->S" : "S->C", flagStr(s.flags).c_str(), s.seq, s.ack);
    }
    if (!c.sawSyn) printf("      (SYN 못 봄 — 캡처가 연결 도중에 시작됐거나 필터에 걸림)\n");
}

// ------------------------------------------------------------
// 단계 2: 방향 하나의 바이트 흐름 복원
// ------------------------------------------------------------
struct Piece {
    enum Kind { DATA, GAP, RETRANSMIT, OVERLAP } kind;
    int64_t from, to;            // 상대 순서번호 [from, to)
    size_t packet = 0;
    std::string bytes;           // DATA/OVERLAP 일 때 실제 이어붙인 바이트
    size_t arrivedBefore = 0;    // out of order: 이 세그먼트가 seq 상 앞선 #n 보다 먼저 도착
};

static std::vector<Piece> reassemble(const Connection& c, bool clientToServer) {
    const std::string& from = clientToServer ? c.client : c.server;
    bool baseSet = false;
    uint32_t base = 0;
    struct Item { int64_t rel; const Segment* seg; };
    std::vector<Item> items;
    for (auto& s : c.segs) {
        if (s.src != from) continue;
        if (!baseSet) { base = s.seq + ((s.flags & SYN) ? 1 : 0); baseSet = true; }   // SYN 없으면 첫 세그먼트 기준
        if (s.payload.empty()) continue;
        items.push_back({int64_t(int32_t(s.seq - base)), &s});                        // int32 차이 = wrap 한 번까지 안전
    }
    std::stable_sort(items.begin(), items.end(), [](const Item& a, const Item& b) { return a.rel < b.rel; });

    std::vector<Piece> out;
    int64_t next = items.empty() ? 0 : std::min<int64_t>(0, items.front().rel);
    size_t latestPacket = 0;                                       // seq 순서로 지나오면서 본 가장 늦은 패킷 번호
    for (auto& it : items) {
        const Segment& s = *it.seg;
        int64_t start = it.rel, end = it.rel + int64_t(s.payload.size());
        size_t outOfOrder = s.packet < latestPacket ? latestPacket : 0;
        latestPacket = std::max(latestPacket, s.packet);
        if (start > next) out.push_back({Piece::GAP, next, start});
        if (end <= next) {
            out.push_back({Piece::RETRANSMIT, start, end, s.packet});
            continue;
        }
        size_t skip = size_t(std::max<int64_t>(0, next - start));
        Piece p{skip ? Piece::OVERLAP : Piece::DATA, start + int64_t(skip), end, s.packet, s.payload.substr(skip)};
        p.arrivedBefore = outOfOrder;
        out.push_back(p);
        next = end;
    }
    return out;
}

static void hexdump(const std::string& b, int64_t baseOffset) {
    for (size_t row = 0; row < b.size(); row += 16) {
        printf("      %08llx  ", (unsigned long long)(baseOffset + int64_t(row)));
        for (size_t i = row; i < row + 16; i++) i < b.size() ? printf("%02x ", uint8_t(b[i])) : printf("   ");
        printf(" ");
        for (size_t i = row; i < row + 16 && i < b.size(); i++) putchar(uint8_t(b[i]) >= 32 && uint8_t(b[i]) < 127 ? b[i] : '.');
        printf("\n");
    }
}

static void printStream(const Connection& c, bool hex) {
    for (bool c2s : {true, false}) {
        auto pieces = reassemble(c, c2s);
        uint64_t got = 0, missing = 0;
        for (auto& p : pieces) {
            if (p.kind == Piece::DATA || p.kind == Piece::OVERLAP) got += p.bytes.size();
            if (p.kind == Piece::GAP) missing += uint64_t(p.to - p.from);
        }
        printf("\n%s  %s -> %s   %llu bytes reassembled, %llu bytes missing\n", c2s ? "C->S" : "S->C", (c2s ? c.client : c.server).c_str(),
               (c2s ? c.server : c.client).c_str(), (unsigned long long)got, (unsigned long long)missing);
        for (auto& p : pieces) {
            switch (p.kind) {
            case Piece::GAP:
                printf("  [%lld..%lld)  GAP  %lld bytes not captured\n", (long long)p.from, (long long)p.to, (long long)(p.to - p.from));
                break;
            case Piece::RETRANSMIT:
                printf("  [%lld..%lld)  #%zu retransmission (already have these bytes, dropped)\n", (long long)p.from, (long long)p.to, p.packet);
                break;
            default:
                printf("  [%lld..%lld)  #%zu%s", (long long)p.from, (long long)p.to, p.packet, p.kind == Piece::OVERLAP ? "  overlap trimmed" : "");
                if (p.arrivedBefore) printf("  out of order: arrived before #%zu", p.arrivedBefore);
                printf("\n");
            }
        }
        printf("  ---- %s ----\n", hex ? "hex" : "text");
        for (auto& p : pieces) {
            if (p.kind == Piece::GAP) printf(hex ? "      «%lld bytes missing»\n" : "«%lld bytes missing»", (long long)(p.to - p.from));
            if (p.kind != Piece::DATA && p.kind != Piece::OVERLAP) continue;
            if (hex) hexdump(p.bytes, p.from);
            else fwrite(p.bytes.data(), 1, p.bytes.size(), stdout);
        }
        if (!hex) printf("\n");
    }
}

int main(int argc, char** argv) {
#ifdef _WIN32
    // Windows 함정: CRT 의 stdout 은 기본이 '텍스트 모드'라서 \n 을 \r\n 으로 바꿔 내보낸다.
    //   복원한 HTTP 바이트의 \r\n 이 \r\r\n 이 되어 "원본 그대로" 가 깨진다 -> 바이너리 모드로.
    _setmode(_fileno(stdout), _O_BINARY);
    SetConsoleOutputCP(CP_UTF8);
#endif
    if (argc < 2) {
        printf("사용법: %s capture.pcap|pcapng [연결번호] [--hex]\n", argv[0]);
        return 1;
    }
    size_t pick = 0;
    bool hex = false;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--hex") hex = true;
        else pick = size_t(std::strtoul(a.c_str(), nullptr, 10));
    }
    std::ifstream in(argv[1], std::ios::binary);
    std::string file((std::istreambuf_iterator<char>(in)), {});
    std::vector<Packet> packets;
    try {
        packets = readCaptureFile(file);
    } catch (const std::exception& e) {
        printf("읽기 실패: %s\n", e.what());
        return 1;
    }
    std::vector<Segment> segs;
    for (size_t i = 0; i < packets.size(); i++) {
        Segment s;
        if (toSegment(packets[i], i + 1, s)) segs.push_back(std::move(s));
    }
    auto conns = group(segs);
    if (pick) {
        if (pick > conns.size()) { printf("연결 %zu 없음 (전체 %zu개)\n", pick, conns.size()); return 1; }
        auto& c = conns[pick - 1];
        printf("[%zu] %s -> %s\n", pick, c.client.c_str(), c.server.c_str());
        printLifecycle(c);
        printStream(c, hex);
        return 0;
    }
    printf("%zu packets, %zu TCP segments, %zu connections\n\n", packets.size(), segs.size(), conns.size());
    for (size_t i = 0; i < conns.size(); i++) {
        auto& c = conns[i];
        uint64_t up = 0, down = 0;
        for (auto& s : c.segs) (s.src == c.client ? up : down) += s.payload.size();
        printf("[%zu] %s -> %s   %zu packets   C->S %llu B   S->C %llu B\n", i + 1, c.client.c_str(), c.server.c_str(), c.segs.size(),
               (unsigned long long)up, (unsigned long long)down);
        printLifecycle(c);
    }
    return 0;
}
