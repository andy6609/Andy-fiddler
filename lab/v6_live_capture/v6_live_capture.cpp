/*
============================================================
 v6_live_capture  —  파일 말고 '지금 선 위에서' 잡기
============================================================
 목적: v4/v5 는 이미 저장된 pcap 파일을 읽었다. 그 파일은 누가 만드나?
       -> libpcap (Windows 는 Npcap) 이 OS 커널/드라이버에 붙어서 지나가는 패킷의 '복사본'을 받아온다.

 어디서 복사해 오나:
   macOS / BSD : /dev/bpf* (Berkeley Packet Filter 장치)   -> root 또는 bpf 그룹 권한 필요
   Linux       : AF_PACKET 소켓                            -> root 또는 CAP_NET_RAW
   Windows     : Npcap 드라이버 (NDIS 필터)                  -> Npcap 설치 필요, 설치 옵션에 따라 관리자 권한
   => 프록시(v1~v3)는 일반 권한으로 되는데 캡처는 권한이 필요한 이유.

 [v6 단계 1]
     ./v6_live_capture                   인터페이스 목록
     ./v6_live_capture en0               en0 에서 캡처 시작, 한 줄 요약 출력, Ctrl+C 로 끝 + 통계
   pcap_open_live(장치, snaplen, promisc, timeout)
     snaplen  : 패킷당 앞에서 몇 바이트까지 복사할지 (65535 = 사실상 전부)
     promisc  : 0 = 내 것만. 1 = 같은 링크의 남의 프레임도 (스위치 환경에선 별 의미 없음)
     timeout  : 커널이 패킷을 모아서 넘겨주는 최대 대기 ms. 0 이면 플랫폼마다 동작이 달라서 100 으로.

 [v6 단계 2]
     ./v6_live_capture en0 -f "tcp port 443" -w out.pcap -c 100
     ./v6_live_capture -r out.pcap -f "udp port 53"        파일을 같은 루프로 다시 읽기 (권한 불필요)
     ./v6_live_capture -r out.pcap -f "tcp" --dump-filter   필터가 컴파일된 BPF 명령어 보기

   BPF 필터 = 커널 안에서 패킷마다 실행되는 작은 '기계어' 프로그램.
     "tcp port 443" 같은 문자열을 pcap_compile 이 명령어 몇십 개로 바꾸고, 커널이 그걸 돌려서
     통과한 패킷만 사용자 공간으로 복사한다. -> 필요 없는 패킷은 복사 비용조차 안 듦.
     --dump-filter 로 보면 "offset 12 의 2바이트가 0x0800 인가(IPv4?)" 같은 비교가 줄줄이 나온다.
     (v4 에서 손으로 따라간 계층 해석을 컴파일러가 대신 짜 준 것)

   -w 로 저장한 파일은 v4/v5 로 그대로 읽힌다 = 캡처 -> 저장 -> 분석 이 이어짐.

 local-proxy-lab / WireScope 본체와의 관계:
   본체 src/capture.cpp 는 Windows 에서 wpcap.dll 을 '실행 중에' LoadLibrary 로 붙인다
   (Npcap 미설치 PC 에서도 프로그램은 뜨고, 캡처 버튼만 '설치 필요'를 보여주려고).
   v6 는 학습용이라 그냥 링크한다 (Windows 빌드엔 Npcap SDK 의 wpcap.lib 필요).
============================================================
*/

#include <pcap/pcap.h>

#include <atomic>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <string>

static std::atomic<bool> g_stop{false};
static void onSignal(int) { g_stop = true; }

static uint16_t be16(const u_char* p) { return uint16_t(p[0] << 8 | p[1]); }

// 한 줄 요약 (v4 의 아주 작은 버전: Ethernet/loopback -> IPv4/IPv6 -> TCP/UDP 포트까지만)
static std::string summarize(int link, const u_char* d, uint32_t caplen) {
    size_t off;
    int version;
    if (link == DLT_EN10MB) {
        if (caplen < 14) return "short frame";
        uint16_t et = be16(d + 12);
        if (et == 0x0806) return "ARP";
        if (et != 0x0800 && et != 0x86dd) return "EtherType " + std::to_string(et);
        off = 14;
    } else if (link == DLT_NULL || link == DLT_LOOP) {      // macOS lo0
        off = 4;
    } else {
        return "link type " + std::to_string(link);
    }
    if (off >= caplen) return "short";
    version = d[off] >> 4;
    char src[64], dst[64];
    uint8_t proto;
    size_t l4;
    if (version == 4 && off + 20 <= caplen) {
        snprintf(src, sizeof(src), "%u.%u.%u.%u", d[off + 12], d[off + 13], d[off + 14], d[off + 15]);
        snprintf(dst, sizeof(dst), "%u.%u.%u.%u", d[off + 16], d[off + 17], d[off + 18], d[off + 19]);
        proto = d[off + 9];
        l4 = off + (d[off] & 15) * 4;
    } else if (version == 6 && off + 40 <= caplen) {
        snprintf(src, sizeof(src), "[ipv6 ..%02x%02x]", d[off + 22], d[off + 23]);   // 한 줄 요약이라 끝 2바이트만
        snprintf(dst, sizeof(dst), "[ipv6 ..%02x%02x]", d[off + 38], d[off + 39]);
        proto = d[off + 6];
        l4 = off + 40;
    } else {
        return "IP?";
    }
    const char* name = proto == 6 ? "TCP" : proto == 17 ? "UDP" : proto == 1 ? "ICMP" : proto == 58 ? "ICMPv6" : "IP";
    if ((proto == 6 || proto == 17) && l4 + 4 <= caplen)
        return std::string(name) + " " + src + ":" + std::to_string(be16(d + l4)) + " -> " + dst + ":" + std::to_string(be16(d + l4 + 2));
    return std::string(name) + " " + src + " -> " + dst;
}

static int listInterfaces() {
    pcap_if_t* devs = nullptr;
    char err[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&devs, err) != 0) {
        printf("pcap_findalldevs 실패: %s\n", err);
        return 1;
    }
    printf("캡처 가능한 인터페이스:\n");
    for (pcap_if_t* d = devs; d; d = d->next)
        printf("  %-24s %s%s\n", d->name, d->description ? d->description : "", (d->flags & PCAP_IF_LOOPBACK) ? " (loopback)" : "");
    pcap_freealldevs(devs);
    return 0;
}

int main(int argc, char** argv) {
#ifdef _WIN32
    setvbuf(stdout, nullptr, _IONBF, 0);   // MSVC: _IOLBF 없음 + 크기 0 이면 즉시 종료 (lab_net.hpp 의 lineBufferedStdout 참고)
#else
    setvbuf(stdout, nullptr, _IOLBF, 0);
#endif
    std::string device, readFile, writeFile, filter;
    uint64_t limit = 0;
    bool dumpFilter = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "-r" && i + 1 < argc) readFile = argv[++i];
        else if (a == "-w" && i + 1 < argc) writeFile = argv[++i];
        else if (a == "-f" && i + 1 < argc) filter = argv[++i];
        else if (a == "-c" && i + 1 < argc) limit = std::strtoull(argv[++i], nullptr, 10);
        else if (a == "--dump-filter") dumpFilter = true;
        else device = a;
    }
    if (device.empty() && readFile.empty()) return listInterfaces();

    char err[PCAP_ERRBUF_SIZE] = {};
    pcap_t* h = readFile.empty() ? pcap_open_live(device.c_str(), 65535, 0, 100, err)
                                 : pcap_open_offline(readFile.c_str(), err);      // pcap/pcapng 둘 다 읽음
    if (!h) {
        // macOS 에서 권한 없으면 여기서: "(cannot open BPF device) /dev/bpf0: Permission denied"
        printf("열기 실패: %s\n", err);
        return 2;
    }
    int link = pcap_datalink(h);

    if (!filter.empty()) {
        bpf_program prog{};
        // optimize=1, netmask 는 broadcast 판별용이라 모르면 PCAP_NETMASK_UNKNOWN
        if (pcap_compile(h, &prog, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
            printf("필터 문법 오류: %s\n", pcap_geterr(h));
            pcap_close(h);
            return 3;
        }
        if (dumpFilter) {
            printf("[v6] \"%s\" -> BPF 명령어 %u개:\n", filter.c_str(), prog.bf_len);
            for (u_int i = 0; i < prog.bf_len; i++) printf("  %s\n", bpf_image(&prog.bf_insns[i], int(i)));
        }
        pcap_setfilter(h, &prog);      // 라이브면 커널에 설치, 파일이면 libpcap 이 사용자 공간에서 적용
        pcap_freecode(&prog);
    }
    pcap_dumper_t* out = writeFile.empty() ? nullptr : pcap_dump_open(h, writeFile.c_str());
    if (!writeFile.empty() && !out) {
        printf("저장 파일 열기 실패: %s\n", pcap_geterr(h));
        return 4;
    }
    printf("[v6] %s 시작 (link type %d = %s)%s%s\n", readFile.empty() ? device.c_str() : readFile.c_str(), link, pcap_datalink_val_to_name(link),
           filter.empty() ? "" : ", filter: ", filter.c_str());
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    uint64_t n = 0;
    while (!g_stop && (!limit || n < limit)) {
        pcap_pkthdr* hdr;
        const u_char* data;
        int r = pcap_next_ex(h, &hdr, &data);       // 1 = 패킷, 0 = timeout(아무것도 없음), -1 = 에러, -2 = 파일 끝
        if (r == 0) continue;
        if (r < 0) {
            if (r == -1) printf("에러: %s\n", pcap_geterr(h));
            break;
        }
        n++;
        if (out) pcap_dump(reinterpret_cast<u_char*>(out), hdr, data);   // 받은 그대로 파일에 (헤더 포함)
        char t[16];
        time_t sec = hdr->ts.tv_sec;
        strftime(t, sizeof(t), "%H:%M:%S", localtime(&sec));
        printf("%-6llu %s.%06ld  %5u B  %s\n", (unsigned long long)n, t, long(hdr->ts.tv_usec), hdr->len, summarize(link, data, hdr->caplen).c_str());
    }

    // 통계: 받은 것 vs 커널/드라이버가 버린 것. drop 이 있으면 v5 에서 GAP 으로 보이게 된다.
    pcap_stat st{};
    if (readFile.empty() && pcap_stats(h, &st) == 0)
        printf("\n[v6] 받음 %llu, 커널 수신 %u, 버퍼 부족으로 drop %u, 인터페이스 drop %u\n", (unsigned long long)n, st.ps_recv, st.ps_drop, st.ps_ifdrop);
    else
        printf("\n[v6] 필터 통과 %llu 패킷\n", (unsigned long long)n);
    if (out) pcap_dump_close(out);
    pcap_close(h);
    return 0;
}
