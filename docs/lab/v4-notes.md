# v4 노트 — 패킷을 세포 단위로

> 코드: `lab/v4_packet_decoder/v4_packet_decoder.cpp`
> 실행: `./build/lab/v4_packet_decoder file.pcapng` (목록) / `... file.pcapng 3 --field "TCP flags"` (상세)

---

## 1. 왜 프록시(v1~v3) 다음에 패킷인가

| 관점 | 프록시 안 (v1~v3) | 선 위 (v4~v6) |
|---|---|---|
| 단위 | 요청/응답, stream | 패킷 (보통 ≤ 1500 바이트) |
| HTTPS | MITM 하면 평문 | **항상 암호문** (TLS 레코드 헤더까지만) |
| 보이는 것 | 의미 (메서드, 헤더, body) | 주소, 포트, 순서번호, 플래그, 크기, 시간 |
| 프록시를 안 거치는 트래픽 | 못 봄 | 봄 (DNS, QUIC, 프록시 무시하는 앱) |

→ WireScope 본체가 둘 다 갖는 이유. 요청에서 시작해 그 연결의 패킷/바이트까지 내려가려고.

---

## 2. ★ 꼭 이해하고 갈 것

### (A) 각 층이 다음 층을 알려준다
```
Ethernet.type=0x0800 → IPv4.protocol=6 → TCP.port=443 → (payload 첫 바이트 0x16, 0x03) → TLS 처럼 생김
```
- 마지막 단계(앱 계층)는 **확신이 아니라 모양**이다. 포트 53 이라고 DNS 라는 보장은 없다. 그래서 v4 는 "query example.com" 처럼 해석한 필드 값을 보여줄 뿐, "DNS 트래픽입니다" 같은 결론을 붙이지 않는다.

### (B) 필드마다 (offset, length)
- `TCP flags  ACK PSH  47  1` = 이 패킷의 47번째 바이트 1개.
- 이걸 들고 있어야 화면에서 **필드 ↔ 바이트**를 연결할 수 있다. 본체 inspector 의 "Fields & bytes" 탭이 그대로 이 구조 (`src/packet.cpp` 의 `fields: [{name, value, offset, length}]`).

### (C) 길이 3종 — 헷갈리기 쉬움
| 길이 | 뜻 |
|---|---|
| caplen (저장된 길이) | 파일에 실제 있는 바이트. snaplen 으로 잘릴 수 있음 |
| origlen (원래 길이) | 선 위에서의 길이 |
| IPv4 total length | IP 패킷 길이. Ethernet 최소 60바이트 맞추려는 **padding 은 여기 밖** |

→ payload 길이를 caplen 으로 계산하면 padding 0 바이트를 데이터로 착각한다. IP 길이로 잘라야 함 (테스트 있음).

### (D) pcap vs pcapng
- pcap: 헤더 24B + (16B 레코드 헤더 + 데이터) 반복. 파일 전체가 link type 하나.
- pcapng: 블록 나열. 인터페이스(IDB)마다 link type 과 시간 단위가 다를 수 있고, 모르는 블록은 길이만 보고 건너뛴다.

### (E) 악의적 입력
- DNS 압축 포인터가 자기 자신을 가리키면 무한 루프 → 방문한 위치 기록으로 차단.
- 모든 길이 필드는 "남은 바이트보다 큰가" 먼저 확인. 해석이 멈추면 **멈춘 위치까지의 필드 + 이유**를 남긴다.

---

## 3. 🟡 안 한 것

- IP fragment 재조립, TCP 옵션 해석, TLS ClientHello 내부(SNI는 v2에서 함), HTTP/2 프레임(암호문이라 선 위에선 불가)
- 체크섬 검증 (캡처 시점의 NIC offload 때문에 0 이거나 틀린 값이 흔함)

---

## 4. 확인한 것 (`tests/lab_smoke.py v4`, 합성 파일)

- classic pcap / pcapng(인터페이스 2개, Ethernet + BSD loopback), IPv6, VLAN, DNS, HTTP 요청줄
- TCP flags = offset 47, `^^` 위치 일치
- DNS 포인터 루프와 잘린 파일은 이유와 함께 보고
- **실제 캡처 파일은 아직 안 넣어 봄** (이 Mac 은 BPF 권한이 없어서 캡처 불가 — v6 노트 참고)
