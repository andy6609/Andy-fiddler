# v6 노트 — 지금 선 위에서 잡기

> 코드: `lab/v6_live_capture/v6_live_capture.cpp`
> 실행: `sudo ./build/lab/v6_live_capture en0 -f "tcp port 443" -w out.pcap` / `./build/lab/v6_live_capture -r out.pcap -f "udp port 53"`

---

## 1. v4/v5 대비 변화

| | v4/v5 | v6 |
|---|---|---|
| 입력 | 저장된 파일 | 라이브 인터페이스 (또는 `-r` 파일 재생) |
| 직접 짠 것 | 파일 형식, 계층 해석 | 거의 없음 — libpcap/Npcap API 사용법 |
| 권한 | 필요 없음 | **필요** (BPF 장치 / Npcap 드라이버) |
| 결과 | 화면 | 화면 + `-w` pcap 저장 → v4/v5 입력 |

---

## 2. ★ 꼭 이해하고 갈 것

### (A) BPF 필터 = 커널에서 도는 작은 프로그램
`"udp port 53"` 을 `--dump-filter` 로 보면 (실제 출력 일부):
```
(000) ldh  [12]                     ; Ethernet type 읽기  (v4: offset 12, 2바이트)
(008) jeq  #0x800   jt 9  jf 19     ; IPv4 인가
(009) ldb  [23]                     ; IPv4 protocol (offset 14+9)
(010) jeq  #0x11    jt 11 jf 19     ; 17 = UDP
(012) jset #0x1fff  jt 19 jf 13     ; fragment offset 이 있으면 버림 (포트가 없는 조각)
(013) ldxb 4*([14]&0xf)             ; IHL x 4 = IP 헤더 길이  (v4 의 ihl 계산과 똑같음)
(014) ldh  [x + 14]                 ; UDP source port
(015) jeq  #0x35 ...                ; 53
(018) ret  #65535                   ; 통과: 65535 바이트까지 복사
(019) ret  #0                       ; 버림
```
- v4 에서 손으로 따라간 계층 해석을 필터 컴파일러가 똑같이 짜 준다.
- 커널에서 거르니까 필요 없는 패킷은 사용자 공간으로 **복사조차 안 된다** → 바쁜 링크에서 drop 을 줄이는 1순위 방법.
- 본체에서 기본 필터가 `not tcp port 17890` 인 이유: UI 자기 트래픽을 캡처하지 않으려고.

### (B) drop 통계
- `ps_drop`: 커널 버퍼가 넘쳐 버린 패킷. 이게 0 이 아니면 v5 에서 **GAP** 으로 나타난다.
- 즉 GAP 을 보면 "네트워크가 잃었나?" 보다 "내 캡처가 따라가지 못했나?" 를 먼저 의심.

### (C) 권한과 플랫폼
| OS | 장치 | 권한 |
|---|---|---|
| macOS | `/dev/bpf*` | root 또는 ChmodBPF(Wireshark 설치 시) |
| Linux | AF_PACKET | root 또는 `CAP_NET_RAW` |
| Windows | Npcap NDIS 필터 | Npcap 설치. "Admin only" 옵션이면 관리자 |

- 이 개발 Mac 은 권한이 없어서 라이브 캡처는 `Permission denied` 로 실패한다 — 테스트도 그 실패 메시지를 확인하는 것으로 되어 있다.
- loopback(127.0.0.1) 트래픽: macOS 는 `lo0`(link type 0, 4바이트 AF 헤더), Windows 는 Npcap 설치 시 "loopback support" 를 켜야 `\Device\NPF_Loopback` 이 생긴다. **클라이언트↔프록시 구간은 loopback** 이라 이게 없으면 본체 "Packets" 탭의 앞 구간이 비어 있다.

### (D) 본체와의 차이
- 본체 `src/capture.cpp` 는 Windows 에서 `wpcap.dll` 을 `LoadLibraryEx` 로 실행 중에 붙인다 → Npcap 없는 PC 에서도 프로그램은 뜨고 캡처만 "설치 필요".
- v6 는 링크 시점에 묶는다 (Windows 빌드는 Npcap SDK 의 `wpcap.lib` 필요, 없으면 CMake 가 v6 만 건너뜀).

---

## 3. 확인한 것 / 못 한 것

- ✅ 인터페이스 목록, 권한 없을 때 OS 에러 그대로 출력 (macOS)
- ✅ `-r` 로 파일 재생 + BPF 필터 적용, BPF 명령어 출력, `-w` 저장 → v5 가 읽음, 잘못된 필터 거절
- ❌ **실제 라이브 캡처는 이 호스트에서 못 돌려봄** (sudo 없이 진행). Windows + Npcap 도 미검증.
- 테스트 중 발견: 합성 파일 두 개가 같은 4-tuple 을 써서 v5 가 한 연결로 합쳤다 → v5 노트의 "연결 재사용 분리 안 함" 한계가 실제로 보인 사례.
