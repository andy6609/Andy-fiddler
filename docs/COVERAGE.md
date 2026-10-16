# WireScope 관찰 범위 보고서 — 볼 수 있는 것과 볼 수 없는 것

- 작성일: 2026-10-15, 갱신 2026-10-16 (로컬 파일 → 요청 추적, Windows 프로세스 귀속, body 한도 설정)
- 기준 코드: `feature/provenance` (main 에 합쳐질 내용)
- 관련 문서: [AI 인수인계](AI-HANDOFF.md), [lab 로드맵](lab/README.md)

---

## 요약

WireScope는 두 경로로 트래픽을 수집한다. **프록시 경로**는 프록시 설정을 따르는 앱의 HTTP/1.x·HTTP/2를 평문으로 기록한다. **패킷 캡처 경로**는 프록시 설정과 무관하게 인터페이스를 지나는 모든 IP 트래픽을 헤더 필드와 원시 바이트 수준으로 기록한다.

- 내용(메서드, 헤더, body)까지 해석되는 것은 HTTP 계열뿐이다.
- 그 밖의 트래픽은 존재, 주소, 포트, 크기, 타이밍, 원시 바이트까지 관찰된다.
- 등록한 **로컬 파일의 어느 부분이 어느 요청 body 에 있었는지**를 찾을 수 있다(provenance). 단, 어느 프로세스가 그 파일을 읽었는지는 아니다.
- 암호화된 비-HTTP 트래픽, QUIC/HTTP3 내용, 인증서 고정을 쓰는 앱의 내용, 파일 I/O 수준 정보는 관찰 범위 밖이다. 보낸 프로세스(PID)는 Windows 에서만 연결 단위로 기록한다.
- 패킷 캡처 경로는 Windows(Npcap) 실환경에서 아직 검증되지 않았다(§5).

---

## 1. 수집 경로

| 경로 | 동작 | 전제 조건 | 코드 |
|---|---|---|---|
| 프록시 | 명시적 HTTP 프록시(기본 `127.0.0.1:18080`). CONNECT 터널은 TLS 종단(MITM) 또는 통과(passthrough) | 클라이언트가 프록시를 사용하도록 설정. TLS 종단 시 로컬 CA 신뢰 | `src/proxy.cpp`, `src/http2.cpp`, `src/tls.cpp` |
| 패킷 캡처 | 선택한 인터페이스에서 Npcap(Windows)/libpcap으로 패킷 복사. BPF 필터 적용 가능 | 캡처 권한, Windows는 Npcap 설치(loopback 포함 옵션) | `src/capture.cpp`, `src/packet.cpp` |
| 파일 가져오기 | `.pcap`/`.pcapng`, `.wscope` 세션 | 없음 | `src/packet.cpp` `readCapture`, `src/core.cpp` `restore` |
| 로컬 파일 스냅샷 | 브라우저(파일/폴더 선택)나 스크립트(`/api/files`)가 넘긴 파일 바이트를 세션에 저장. 엔진이 경로를 스스로 열지는 않음 | 파일당 2 MiB, 합계 32 MiB, 256개 | `src/core.cpp` `LocalFile`, `web/provenance.js` |

두 경로는 연결 key(정렬한 endpoint 쌍)로 이어진다. 프록시가 기록한 요청에서 같은 TCP 연결의 패킷으로 이동할 수 있다. 이 매칭은 **연결 단위**이며 요청 하나와 패킷 하나의 일대일 대응이 아니다. keep-alive나 HTTP/2 다중화로 한 연결에 여러 요청이 실리기 때문이다.

---

## 2. 볼 수 있는 것

### 2.1 프록시 경로

| 대상 | 관찰 수준 | 비고 |
|---|---|---|
| HTTP/1.0, HTTP/1.1 (평문) | 요청줄, 헤더(순서 유지), body, 상태, 타이밍, chunked trailer | Content-Length / chunked / 연결 종료 framing 모두 처리 |
| HTTPS + TLS 종단 (HTTP/1.1) | 위와 동일한 평문 + TLS 버전, cipher, ALPN | 로컬 CA를 신뢰하는 클라이언트에 한함 |
| HTTPS + TLS 종단 (HTTP/2) | stream별 요청/응답: 의사 헤더(`:method`, `:path`, `:status`), 헤더, body, trailer, stream ID, DATA 프레임 수, RST_STREAM | 클라이언트·서버 모두 h2를 협상한 경우 |
| HTTPS, TLS 통과 모드 | 목적지 host:port, 방향별 바이트 수, 타이밍, 암호화된 바이트 원본 | 내용은 암호문 |
| WebSocket (HTTP/1.1 Upgrade) | 업그레이드 요청/응답은 평문, 이후 양방향 원시 바이트 | 프레임 단위 해석 없음 |
| SSE (`text/event-stream`) | 이벤트 단위 분리, 이벤트 이름별 개수, 필드 경로 기준 이어붙이기 | UI 기능 (`web/app.js`) |
| 압축 body | gzip / deflate는 화면에서 디코딩, 원본 바이트 보존 | br / zstd는 인코딩된 바이트 그대로 |
| 실패 | 업스트림 연결 실패, TLS 검증 실패, 스트림 리셋 등을 error 기록으로 남김 | 오류 메시지 원문 보존 |

### 2.2 패킷 캡처 경로

| 대상 | 관찰 수준 | 비고 |
|---|---|---|
| 링크 계층 | Ethernet(VLAN 포함), BSD loopback, raw IP, Linux SLL/SLL2 | link type 기준 |
| IPv4 / IPv6 | 주소, TTL/hop limit, 프로토콜, IPv6 확장 헤더 체인 | IP fragment는 표시만, 재조립 안 함 |
| TCP | 포트, seq/ack, 플래그, payload 위치. 연결 단위 바이트 흐름 미리보기(gap 표시) | 방향별 1 MiB까지, 완전한 재조립이 아님 |
| UDP | 포트, 길이, payload | |
| DNS | 트랜잭션 ID, 플래그, 질의 이름, 질의 타입 | 응답 레코드(Answer)는 해석 안 함 |
| TLS (TCP 위) | 레코드 종류(Handshake / Application Data 등), 버전, 길이 | 내용은 암호문 |
| 평문 HTTP (TCP 위) | 첫 줄(요청줄 / 상태줄) | 상세 해석은 프록시 경로 몫 |
| ICMP / ICMPv6, ARP | 타입, 코드 / 프로토콜 표시 | |
| 그 외 모든 IP 트래픽 | 주소, 포트, 크기, 타이밍, 원시 바이트 | 프록시를 무시하는 앱 포함 |

모든 해석 필드는 (offset, length)를 함께 기록한다. 화면에서 필드와 바이트 위치를 서로 강조해 확인할 수 있다.

### 2.3 로컬 파일 → 요청 (provenance)

| 대상 | 관찰 수준 | 비고 |
|---|---|---|
| 심어 둔 canary 토큰 (`WSCANARY-…`) | 어느 요청·방향·위치에 있었나 / 한 번도 안 나왔나 / 어느 파일에도 없는데 트래픽에 있나 | 무작위 토큰이라 출처가 모호하지 않음 |
| 텍스트 파일의 줄 | 연속된 줄 run 이 어느 body view 에 있었나, 파일별 커버리지(본 줄 수 / 의미 있는 줄 수) | 앞뒤 공백 무시, 사소한 줄은 시작 불가, 줄번호 접두어 자동 제거 |
| 문장 안에 인용된 긴 줄 | 40자+ 고유 줄의 부분 문자열 일치 (fragment) | |
| 바이너리 파일 | 파일 바이트 전체 / 최장 앞부분(4 KiB 단위) | 이미지·문서 업로드 |
| body 안의 모든 글 | 검색 (Find in bodies) | gzip·JSON·SSE·base64·multipart·form 해제 후 |

각 일치에는 어떤 변환을 거쳐 일치했는지(`gzip`, `json`, `sse`, `join`, `base64`, `multipart`, `line-numbers`)가 붙는다. 자세한 규칙: [PROVENANCE.md](PROVENANCE.md).

### 2.4 기록·비교·내보내기

| 기능 | 내용 |
|---|---|
| body 보관 | 방향별 앞 1 MiB 보관(`--body-limit` 으로 최대 32 MiB), 전체 크기는 끝까지 기록. 잘린 body에는 sha256을 기록하지 않음. 적용된 한도는 archive 에 `bodyLimit` 으로 남음 |
| 요청 비교 | JSON 잎 경로 단위 추가·삭제·변경, side-by-side 줄 비교. 무시 경로와 키 정렬 적용 여부를 화면에 표시 |
| 내보내기 | `.wscope` 세션(재가져오기 가능, 로컬 파일 스냅샷 포함), `.pcapng`, 단일 파일 HTML 보고서(오프라인 뷰어·provenance 포함, 패턴 기반 redact 선택 — redact 하면 스냅샷은 통째로 빠짐) |

---

## 3. 조건부로 보이는 것

| 상황 | 조건 | 조건이 안 맞으면 |
|---|---|---|
| 브라우저 HTTPS | OS/브라우저 신뢰 저장소에 로컬 CA 등록 | TLS 핸드셰이크 실패 기록만 남음 |
| Node.js 기반 CLI | `HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS` | 프록시를 안 쓰거나 인증서 오류 |
| Python 클라이언트 | `HTTPS_PROXY` + `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` | 동일 |
| 클라이언트↔프록시 구간 패킷 | loopback 인터페이스 캡처 (Windows: Npcap loopback 지원 설치 옵션) | 요청의 "Packets" 탭에서 앞 구간이 비어 있음 |
| 프록시↔서버 구간 패킷 | 외부 인터페이스 캡처 | 뒤 구간이 비어 있음 |
| HTTP/2 평문 기록 | 클라이언트와 업스트림이 모두 h2 협상 | 클라이언트만 h2이면 연결 오류. h2→h1 변환은 지원하지 않음 |
| 브라우저 트래픽이 TCP로 오는 것 | 프록시 설정 시 브라우저가 QUIC 대신 TCP를 쓰는 것이 일반적 | QUIC로 나가면 프록시에 안 잡히고 UDP 443 패킷으로만 보임. **실제 클라이언트별 미확인** |

---

## 4. 볼 수 없는 것

| 대상 | 이유 | 현재 대안 |
|---|---|---|
| QUIC / HTTP/3 내용 | UDP 위 자체 암호화, 프록시가 중계하지 않음 | 패킷 경로에서 존재·주소·크기·타이밍만 |
| 인증서 고정(pinning) 앱의 내용 | 로컬 CA로 서명한 인증서를 거부 | TLS 통과 모드의 바이트·타이밍, 실패 기록 |
| 자체 trust store를 쓰고 설정 수단이 없는 앱의 내용 | 로컬 CA를 신뢰하게 만들 방법이 없음 | 동일 |
| 프록시 설정을 따르지 않는 앱의 내용 | 명시적 프록시만 지원, 강제 리다이렉트(WFP 등) 없음 | 패킷 경로에서 바이트 수준 |
| 비-HTTP 프로토콜의 의미 해석 | 전용 파서 없음 (WebSocket 프레임, gRPC protobuf, MQTT, IMAP 등) | 원시 바이트, TLS 위라면 레코드 수준 |
| h2c (평문 HTTP/2), HTTP/2 server push | 미구현 / push 비활성화 | — |
| DNS 응답 내용, DNS over HTTPS/TLS | Answer 파서 없음 / 암호화 | 질의 이름까지만 / HTTPS·TLS 수준 |
| 어떤 프로세스(PID)가 보낸 트래픽인지 (macOS/Linux) | 프로세스 귀속은 Windows TCP 연결 표로만 구현 | Windows 에선 연결 단위로 PID·exe·명령줄 기록. 그 외엔 세션 메타데이터를 사람이 기록 |
| 어느 프로세스가 어느 파일을 **읽었는지** | 네트워크 밖의 일. 파일 I/O 추적(hook/ETW/fs_usage) 없음 | provenance 로 "그 파일의 내용이 어느 요청에 있었는지"까지는 확인 |
| 요약·번역·재작성돼서 나간 파일 내용 | 줄·바이트가 그대로 남은 경우만 비교. 의미 유사도 판정은 일부러 안 함 | — |
| 캡처가 놓친 바이트 | 드라이버 drop, 필터, 캡처 시작 전 구간 | TCP 미리보기에 GAP으로 표시하며 채워 넣지 않음 |
| 보관 한도를 넘은 기록 | body 방향별 1 MiB(설정으로 32 MiB까지), 요청 3000건, 패킷 16000개, body·패킷 각 64 MiB | 전체 크기와 축출(evicted) 수는 기록. 패킷 표는 최신 5000개. provenance 는 보관된 바이트만 검색하고 그 사실을 화면에 적음 |

---

## 5. 검증 상태

| 항목 | 상태 | 근거 |
|---|---|---|
| HTTP/1.1, chunked, 1.5 MiB body, TLS 종단·통과, HTTP/2 병렬 5 stream·trailer·POST, 오류 기록, `/api/files` | macOS에서 검증, Windows 러너(CI)에서 같은 테스트 | `tests/integration_test.py` (58개 검증 항목) |
| 패킷 디코딩, pcap/pcapng, TCP 미리보기 gap, 세션 복원, 보고서 escape, 로컬 파일 스냅샷, body 한도 | macOS + Windows 러너 | `tests/core_tests.cpp` (128개 검증 항목) |
| provenance 판정 (view·검색·canary·줄 run·fragment·바이트·중복 정리) | node 에서 검증 (macOS + Windows 러너) | `tests/provenance_test.mjs` (71개 검증 항목) |
| 실험 키트 전체 (정답을 아는 가짜 에이전트) | macOS + Windows 러너 | `tests/experiment_dryrun_test.py` (14개 검증 항목) |
| UI 화면 (목록, 상세, SSE, gzip, 비교, 패킷 hex, 오프라인 보고서) | headless Chrome으로 조작 확인 | 개발 중 스크린샷 |
| 라이브 패킷 캡처 | **미검증** — macOS 개발 호스트에 BPF 권한 없음 | 합성 파일로만 확인 |
| Windows 빌드 | GitHub Actions Windows 러너에서 MSVC 빌드 + 테스트 통과 | `.github/workflows/windows.yml` |
| Npcap, loopback 캡처, Windows 인증서 저장소, 실제 Windows 데스크톱 | **미검증** | 러너에 Npcap 드라이버 없음, 대화형 신뢰 확인창 |
| 실제 에이전트로 실험 001 | Claude Code 2.1.275 로 1회 (macOS, 2026-10-16) | [실행 1](../experiments/001-agent-file-egress/runs/2026-10-16-claude-code-2.1.275.md). 한 번의 관찰 |
| 실제 브라우저 트래픽, 다른 AI 클라이언트, Windows 에서의 에이전트 | **미검증** | |
| 브라우저의 프록시 설정 시 QUIC 미사용 여부 | **미검증** | §3의 일반적 동작 기술 |

---

## 6. 확장 후보

| 후보 | 얻는 것 | 비고 |
|---|---|---|
| WebSocket 프레임 해석 | 업그레이드 이후 트래픽을 메시지 단위로 확인 | 프록시 경로의 기존 바이트에 적용 가능 |
| QUIC Initial 패킷의 SNI 추출 | 프록시 없이 HTTP/3 연결 대상 확인 | Initial은 공개된 방식으로 유도한 키로 보호되어 해독 가능. QUIC 실사용 여부 확인에 직접 연결 |
| DNS 응답 해석 | 패킷 목록의 IP를 도메인과 연결 | |
| 메인 프록시에 SNI 기록 | TLS 통과 모드에서도 접속 대상 host 기록 | `lab/v2_tls_recorder`에 구현된 파서 이식 |
| br / zstd 디코딩 | 압축된 응답 body 확인 (provenance 검색 대상도 넓어짐) | 브라우저 API 미지원, 엔진 쪽 구현 필요 |
| 파일 I/O 추적과 provenance 연결 | "이 프로세스가 이 파일을 읽고 → 이 요청에 실었다"까지 | macOS `fs_usage`, Windows ETW/Process Monitor 기록을 시간·PID 로 맞춤. 권한·드라이버 부담이 커서 별도 단계 |
