# WireScope — 다음 AI를 위한 인수인계

작성일: 2026-10-15, 같은 날 두 번째 세션에서 구현 상태를 갱신했다. 이 문서는 대화 맥락과 디스크 상태를 연결하는 시작점이다.

> **추가 (2026-10-16, `feature/provenance` → main)**: 로컬 파일 → 요청 추적(provenance)을 넣었다. 사이드바 TRACE 아래 *Find in bodies* 와 *Local files → requests*, 판정은 `web/provenance.js`(브라우저·보고서·node 공용), 엔진에는 로컬 파일 스냅샷(`/api/files`)과 `--body-limit`. 실험 키트는 `experiments/001-agent-file-egress/`(가짜 에이전트 dry run 까지만, 실제 에이전트는 아직). 설계·한계: [PROVENANCE.md](PROVENANCE.md). 학습용 축소판: `lab/v11_provenance`.
>
> **현재 상태 (2026-10-15 두 번째 세션)**: 엔진, `web/app.js`, 테스트가 있다. macOS 개발 호스트에서 빌드, 단위 테스트, curl/nghttpd를 이용한 end-to-end 테스트, headless Chrome UI 조작까지 통과했다. **Windows 빌드, Npcap 실제 캡처, Windows 인증서 저장소, 실제 AI 서비스·에이전트 트래픽은 아직 검증하지 않았다.** 아래에서는 “구현됨”과 “검증됨”을 구분한다.

> **`windows` 브랜치 (2026-10-15 세 번째 세션)**: 사용자 요청 "브랜치 하나 파서 윈도우 버전으로 또 만들어봐". MSVC + vcpkg 빌드, C++17, Windows 전용 기능(프록시 연결 → 프로세스 귀속, 시스템 프록시 켜기/복원), lab v9·v10, GitHub Actions Windows CI 를 추가했다. **Windows 검증은 GitHub Actions 러너(Windows Server 2025)에서 돌린 테스트 결과뿐이다.** 실제 Windows 데스크톱 실행, Npcap 캡처, 인증서 신뢰 설치는 여전히 미검증. 무엇이 확인됐고 무엇이 아닌지, Windows 에서만 다르게 동작한 곳 11개는 [WINDOWS.md](WINDOWS.md) 가 기준이다.

관련 문서: [Windows 버전](WINDOWS.md), [오픈소스 조사와 채택한 특징](OPEN-SOURCE-REFERENCES.md), [프로젝트 입구](../README.md).

## 1. 사용자가 만들려는 것과 이유

Windows에서 네트워크를 직접 관찰하고 증명하는 C++ 도구. 프록시를 더 잘 이해하고 실제 패킷과 바이트가 어떻게 오가는지 낮은 단계까지 들여다보려는 학습 프로젝트다. Fiddler와 Wireshark를 엄격히 구분해서 범위를 축소하기보다, **연결·요청 중심 화면에서 시작해 패킷과 바이트로 내려가는 탐색 방식**을 사용자가 선호했다.

우선순위:

1. 인턴 중 배운 네트워크 지식을 이어가고, 멘토가 제안한 Fiddler 같은 검사 창을 직접 만들어 원리를 이해한다.
2. 관찰 근거를 보여줄 수 있는 프로젝트를 만들고, CV와 면접에서 깊이 있는 이야기를 할 수 있게 한다.
3. 기존 인턴 전 C++ 프로젝트보다 의미 있는 결과물을 만든다.

사용자는 우선 AI로 구현하고 이후 면접 준비 시 탑다운으로 공부할 계획이라고 명시했다. 따라서 코드, 구조, 검증 근거와 한계를 추적하기 쉬워야 한다. 지금부터 교육 질문을 반복하거나 다시 기획 단계로 돌리지 않는다.

사용자가 확정한 방향:

- **Windows 우선. Mac 제품 지원은 신경 쓰지 않는다.** 현재 개발 호스트가 macOS인 것과 목표 OS는 별개다.
- HTTP만이 아니라 가능한 넓은 트래픽을 보고 싶다. TCP/UDP/DNS 및 패킷 수준 접근도 포함한다.
- AI 서비스와 여러 코딩 에이전트의 요청을 실제로 관찰하는 사용 사례가 중요하다.
- 요청 간 구조적 차이 비교와 **독립 HTML 뷰어 내보내기**를 좋다고 명시했다.
- ‘파일 전송으로 판단했습니다’ 같은 자동 해설/판정 문구는 매우 싫어한다. 헤더, 메서드, 바이트, 타이밍, 스트림, 연결 등 원자료와 탐색 도구를 보여준다.
- 구현 지시는 ‘일단 한번 다 만들어봐’였다. 첫 세션(Codex)은 엔진 초안과 이 문서를 남겼고, 두 번째 세션(Claude Code)이 빌드 수정, 버그 수정, UI, 테스트를 완성했다.
- 사용자가 다시 확인한 핵심 동기: 프록시를 더 잘 이해하고 실제 패킷이 어떻게 오가는지 “세포 단위”까지 보기 위해, 멘토가 만들어 보라고 해서 만든다. 요청 간 구조 비교, 독립 HTML 뷰어, 여러 코딩 에이전트 대상 실험을 좋은 방향으로 확정했다.

이전 대화의 ‘C이고 A로도 증명했다’, ‘두 번째까지’는 선택지 원문이 이 인수인계에 남아 있지 않다. 문자의 뜻을 새로 추측하지 않는다. 위의 구체적인 사용자 발언을 기준으로 이어간다.

## 2. 인턴십과 멘토 대화의 맥락

인턴 과제는 회사 제품 전체를 만드는 일이 아니라 PoC와 트래픽 관찰을 위한 학습이었다. 멘토들은 이미 조사를 진행했고 실제 프록시 제품도 개발 중이었다. 인턴에게 프록시를 처음부터 만들게 한 이유는 각 AI 이용 방식에서 데이터가 네트워크로 어떻게 이동하는지 확인하도록 하기 위해서였다. 예를 들어 Gemini의 resumable 업로드 동작이 실질적인 관심 대상이었다.

핵심 교훈: **서비스명 하나로 전송 방식을 단정할 수 없다.** Claude 웹·앱·CLI·Cowork 등 환경에 따라 다르다. 사용자의 메모에 있던 ‘무조건 멀티파트’는 ‘무조건 multipart라고 생각하면 안 된다’의 일부였다.

멘토는 프록시 전담이라기보다 파일 I/O 담당이며, 파수의 파일 보안 업무에서 hook을 이용해 파일 열기·닫기·암호화 등 낮은 계층을 다뤘다. 그 경험이 AI를 통한 파일 이동을 파악하는 프로젝트와 연결되었다. 사용자에게 Fiddler로 데이터 흐름을 보고, 더 깊게는 리버스 엔지니어링 관점에서 분석하며, 다음 단계로 검사 창을 만들어보라고 조언했다.

멘토가 설명한 확장 가능성:

- 파일 바이너리/내용 확보, 로컬 파일 I/O 추적과 네트워크 메타데이터의 매칭.
- 원본 파일을 그대로 전송하지 않고 일부 추출·가공한 경우의 관찰.
- 서버 프록시는 단말의 로컬 파일 I/O를 직접 추적할 수 없다는 한계. 메모의 ‘서버라 트래픽 추적 못함’을 모든 서버 네트워크 관찰 불가능이라는 뜻으로 읽으면 안 된다.
- 로컬 프록시, 서버 프록시, 로컬에서 사용자 식별자를 전달하는 하이브리드 등 배치 설계.
- 사용자 세션별 프록시와 시스템 공용 프록시의 정책·효율·장애 격리 비교.
- QUIC 실제 사용 여부, HTTP/1·2, 스트림 처리, OS 세션과 프로세스 이해.

사용자 정정: 내용 확보까지 말한 것이 맞다. 하이브리드 등 설명은 **설계 예시와 검토 중인 아이디어**였다. 이미 배포된 회사 제품의 확정 구조라고 쓰지 않는다. 사용자는 자기 구현과 멘토의 제품 확장 범위를 구분하고 있으므로 이 점을 반복해서 훈계하지 않는다.

면접 조언: 구현했다고 과장하기보다 직접 확인한 환경·메서드·헤더·흐름을 설명한다. 문제와 제약, 선택 이유, 대안과 장단점을 말할 수 있어야 한다. 모르는 내용은 아는 범위를 밝혀 답하고 반론을 받아 판단을 수정할 수 있어야 한다. AI 사용 여부 자체보다 설계·이해·검증 과정이 중요하다. 대본을 써서 연습한다. 메모의 ‘분석해본 것처럼’은 실제로 하지 않은 분석을 했다고 말하라는 지침으로 계승하지 않는다.

기존 정리본: `/Users/andy6609/Desktop/인턴_마지막날_멘토님_조언_정리.md` (이전 작업에서 생성). 이번 문서는 그 파일에 의존하지 않고 핵심 맥락을 포함한다.

## 3. 저장소와 작업 경계

현재 프로젝트 루트: `/Users/andy6609/projects/Andy-fiddler`

2026-10-15 사용자 요청으로 `local-proxy-lab/WireScope/` 내용을 이 저장소 루트로 이동했다. 대상 저장소의 `.git`은 유지했으며 기존 README는 `docs/INITIAL-README.md`에 보존했다. 아래 기존 인턴 자료 경로는 `/Users/andy6609/projects/local-proxy-lab` 기준이다.

- `proxy_ToInfinity/`: 기존 인턴 프록시와 조사 문서.
- `Infinity_v2/`: 기존 확장 설계/코드. 라우터와 MultipartHandler가 있고, Gemini/Presigned 전용 핸들러가 구현되었다고 가정하지 않는다.
- `docs/`, `Report_docs/`, `proxy_beyond_docs/`: 기존 학습, 설계, 보고서.
- **현재 `Andy-fiddler/`: 이번에 새로 작성한 프로젝트.** WireScope는 코드의 제품/실행 파일 이름이다. 기존 프록시를 덮어쓰지 않았다.
- `About-DeepLearning/`, `proxy_ToInfinity/docs/logs/`: 원래 있던 untracked 사용자 자료. 삭제하거나 정리하지 않는다.

이 저장소는 `https://github.com/andy6609/Andy-fiddler`에 연결되어 있고, 원격에는 README 한 줄짜리 첫 커밋만 있다. 이후 작업은 아직 커밋하지 않았다(커밋·푸시는 사용자 요청 시). 저장소에 적용되는 AGENTS.md는 앞선 조사에서 발견하지 못했으며, 다음 AI는 작업 시 다시 적용 지침을 확인하면 된다.

## 4. 현재 아키텍처 선택

사용자가 확정한 제품 요구와 구현 담당 AI가 택한 기술 방식을 구분한다. **C++ 엔진 + 로컬 브라우저 UI**는 구현 선택이다. 네이티브 Qt 창이 아니다. 같은 HTML/CSS/JS 검사 화면을 독립 보고서에서 재사용하려는 선택이다.

```text
대상 앱 ── 명시적 프록시 설정 ──> C++ Proxy (기본 127.0.0.1:18080) ──> 원격 서버
                                   │ HTTP flow / TLS / h2 기록
선택 네트워크 인터페이스 ── Npcap ──┤ 패킷 / TCP·UDP / DNS / raw bytes
                                   ▼
                            메모리 Store
                                   │ 로컬 JSON API
                                   ▼
                    브라우저 검사 UI (127.0.0.1:17890)
                                   │
                    .wscope / pcapng / 독립 HTML
```

두 수집 경로를 함께 둔다. 패킷 캡처와 HTTPS 복호화는 같은 기능이 아니다. HTTPS 평문은 신뢰된 로컬 CA를 통한 MITM 대상 연결에서만 얻는다. 프록시를 우회한 트래픽도 선택 인터페이스에서 캡처할 수 있지만 평문 해독이 자동으로 되는 것은 아니다.

프록시와 캡처는 실행 즉시 시작하지 않는다. CA 신뢰 설치/삭제는 명시적 동작으로 제공한다. 시스템 프록시를 자동 변경하지 않는다. Npcap 드라이버를 번들링하지 않고 Windows의 설치된 라이브러리를 동적 로드하는 코드가 있다.

## 5. 파일별 현재 상태

| 파일 | 내용 | 검증 |
|---|---|---|
| `CMakeLists.txt` | C++17, OpenSSL, nghttp2, Threads, Windows 링크, 비Windows libpcap, 매 빌드마다 웹 자산 복사, CTest(core + integration) | macOS 클린 빌드 경고 0 |
| `src/core.hpp/.cpp` | Flow/Packet/Store, body 캡(기본 1 MiB, `--body-limit` 최대 32 MiB), 로컬 파일 스냅샷(`LocalFile`, 2 MiB/32 MiB/256개), base64/SHA256, 세션 저장·복원(검증 후 교체, 예전 archive 호환), redact(스냅샷 제외), HTML 보고서, 합성 sample | 단위 테스트 |
| `src/packet.hpp/.cpp` | Ethernet/VLAN/IP/TCP/UDP/DNS/TLS 필드와 offset, pcap/pcapng 읽기·쓰기, TCP preview | 단위 테스트(경계·잘림·DNS 포인터 루프·패딩) |
| `src/capture.cpp` | Windows Npcap 동적 로드, 인터페이스/BPF/캡처 스레드/통계. `pcap_stat` 은 Npcap SDK 1.16 헤더대로 6필드 | macOS libpcap 경로는 인터페이스 목록만 확인(BPF 권한 없음). Windows 러너에선 "Npcap 미설치" 경로만. **라이브 캡처 미검증** |
| `src/net.hpp` | socket/Channel/TLS/Proxy 인터페이스 | integration 테스트로 간접 검증 |
| `src/tls.cpp` | 로컬 CA/leaf 생성, ALPN, upstream 검증, filesystem 경로 기반 PEM I/O, DER SHA-256 지문, Windows 사용자 ROOT 신뢰 | 지문은 openssl 출력과 일치. **신뢰 설치는 Windows 미검증** |
| `src/proxy.cpp` | HTTP/1 중계, CONNECT, MITM/passthrough, framing, chunked trailer 기록, Upgrade 터널 | integration 테스트 |
| `src/http2.cpp` | 양방향 nghttp2 세션, 스트림 매핑, 터널 포트 기반 `:authority` 확인, 요청·응답 trailer 전달과 기록, 종료 조건 | integration 테스트(비443 포트, 5개 병렬 스트림, trailer, POST) |
| `src/main.cpp` | 로컬 API, token/Host/Origin 검사, 정적 파일, CLI, Windows 브라우저 열기 | integration 테스트(403 경계 포함) |
| `web/index.html`, `web/app.css` | 컨테이너, 밀도 높은 검사 도구 스타일 | Chrome 1440×900 스크린샷 |
| `web/app.js` | 실시간/오프라인 공용 UI(아래 7절) + TRACE 화면(Find in bodies, Local files → requests, 파일 추가/삭제, 일치 inspector) | headless Chrome CDP 조작, JS 오류 0 |
| `web/provenance.js` | body → view(gzip·JSON·SSE·join·base64·multipart·form), 검색, canary, 줄 run, fragment, 바이너리, 중복 정리, 커버리지. 브라우저·보고서·node 공용 | `tests/provenance_test.mjs` 71개 |
| `scripts/provenance_cli.mjs` | `.wscope` 를 터미널에서 분석, `--files DIR`, `--json` | 실험 dry run 에서 사용 |
| `experiments/001-agent-file-egress/` | 실험 절차, `make_sandbox.py`(canary 저장소), `run_agent.py`(에이전트 하나 기록), `fake_agent.py`(정답 아는 가짜) | `tests/experiment_dryrun_test.py` 14개. **실제 에이전트 미실행** |
| `src/process.cpp` | accept 직후 `GetExtendedTcpTable` 로 연결 → PID, exe/경로/명령줄/부모 | Windows 러너: 직접 띄운 curl/python 의 PID·경로·명령줄·부모와 일치 |
| `src/sysproxy.cpp` | WinINET 시스템 프록시 켜기/복원, 백업 파일, 비정상 종료 감지 | Windows 러너: 레지스트리 반영, 프록시 인자 없는 Python urllib 가 따라옴, 4가지 복원 경로 |
| `tests/core_tests.cpp` | 소켓 없는 단위 테스트 (128개) | 통과 (macOS). Windows 러너는 provenance 머지 후 CI 결과로 확인 |
| `tests/integration_test.py` | curl → WireScope → 로컬 HTTP·HTTPS·nghttpd(h2) 서버, 58개 검사(`/api/files`, provenance.js 인라인 포함). nghttpd 가 없으면 `tests/h2_server.py` | 통과 (macOS) |
| `tests/windows_test.py` | 프로세스 귀속, 시스템 프록시(CI 에서만), 한글 `--data` 경로 | Windows 러너 |
| `third_party/` | cpp-httplib, nlohmann/json 단일 헤더와 LICENSE | — |

| `lab/` (v1~v11) + `docs/lab/` | 사용자 요청(2026-10-15)으로 local-proxy-lab 처럼 개념별 학습 버전을 한국어 주석으로 만듦(v9·v10 은 Windows 세션, v11 은 provenance 축소판). 본체와 코드 공유 없음 | `tests/lab_smoke.py` macOS 94개 검사 통과, v6 라이브 캡처는 미검증 |

**없는 것**: Windows 실제 캡처 증거, 실제 Windows 데스크톱에서의 실행 기록, 실제 AI 서비스/에이전트 실험 기록. (빌드 스크립트·vcpkg manifest·Windows CI 는 windows 브랜치에서 만들어 2026-10-16 main 에 합쳤다.)

사용자 작업 스타일 참고: local-proxy-lab 처럼 버전을 나눠 쌓고, 한국어 주석(목적/핵심/흐름/이전 버전 대비 변화/함정/한계)을 두껍게 달고, 커밋을 작게 자주 나누는 것을 선호한다.

## 6. 데이터와 API 계약

`src/core.hpp`, `Flow::detail()`, `Packet::detail()`, `Store::snapshot()`를 먼저 읽는다. 정확한 필드명은 코드가 기준이다.

- Flow: 메서드/host/path/protocol/상태/연결 ID 등 meta, request/response headers와 body, timeline, messages, notes.
- Body: base64, captured, total, truncated, sha256. 본문 보관은 방향별 1 MiB, 총량은 따로 센다. 전체를 확보하지 못하면 전체 파일 해시라고 주장하면 안 된다.
- Packet: raw bytes의 base64, link type, interface/device, time, parsed fields의 offset/length, endpoint/connection key.
- 상관관계: 프록시 양쪽 소켓의 endpoint key와 패킷 key를 연결하는 초안. 특정 HTTP/2 요청과 특정 암호화 패킷의 일대일 대응 증거는 아니다.
- 세션: name/client/action/notes/sample. 클라이언트 및 실험 환경 기록에 활용한다.
- sample: `.example` 호스트를 쓰는 합성 데이터. 실제 AI 서비스에서 수집한 증거가 아니다.

기본 UI 포트 `17890`, 프록시 포트 `18080`. `GET /api/bootstrap`의 token을 이후 `X-WireScope-Token`에 넣는다.

| API | 용도 |
|---|---|
| `GET /api/state?revision=...` | 변경된 Store 스냅샷 및 capture/proxy 상태 |
| `GET /api/interfaces` | 캡처 인터페이스 |
| `GET /api/flows/{id}`, `/api/packets/{id}` | 상세 |
| `GET /api/stream?key=...` | TCP preview |
| `POST /api/capture/start`, `/stop` | `{device, filter}`로 시작 / 중지 |
| `POST /api/proxy/start`, `/stop` | `{port, mitm}`로 시작 / 중지 |
| `POST /api/session`, `/api/session/new` | 메타데이터 수정 / 새 세션 |
| `POST /api/sample` | 합성 샘플 로드 |
| `POST /api/flows/{id}/notes` | `{notes}` 저장 |
| `GET /api/session/download` | 전체 `.wscope` |
| `POST /api/session/import` | JSON archive 복원 |
| `POST /api/pcap/import` | pcap/pcapng 바이너리 가져오기 |
| `GET /api/pcap/download` | pcapng 저장 |
| `POST /api/report` | `{redact, ids?}` HTML 생성 |
| `GET /api/ca`, `POST /api/ca/create` | CA 상태 / 생성 |
| `POST /api/ca/trust` | `{install}` Windows 사용자 신뢰 설치/삭제 |

세션 교체는 프록시와 캡처를 중지한 상태에서만 가능하다. HTML 보고서는 `window.WIRESCOPE_ARCHIVE`에 데이터를 넣고 `app.js`를 인라인한다. `app.js`는 이 값이 있으면 오프라인 모드로 동작한다(네트워크 없음, 편집·캡처 버튼 숨김). 그래서 `app.js`에는 `</script`나 `<!--` 문자열이 들어가면 안 되고, 단위 테스트가 이를 검사한다.

flow meta에 `port`가 추가되었고, HTTP/1 `protocol`은 실제 요청 버전(`HTTP/1.0` 또는 `HTTP/1.1`)이다. chunked/h2 trailer는 `requestTrailers` / `responseTrailers`(헤더와 같은 [name, value] 배열)로 기록한다.

## 7. 화면 구현을 이어갈 설계

밀도 높은 분석 도구 스타일: 흰색/슬레이트 바탕, 파란 강조, Segoe UI와 Cascadia Code. 마케팅 카드나 자동 판단 문장보다 데이터 테이블과 상세 검사에 집중한다.

- 왼쪽: 트래픽 종류와 연결 목록, 필터.
- 가운데: 요청/패킷 테이블, 검색, 두 요청 선택과 비교 진입.
- 오른쪽: 개요, request, response, headers/body, bytes/hex, protocol fields, timeline, related packets, stream, notes 탭.
- hex의 필드 범위 강조와 원시 바이트 다운로드.
- JSON/text/hex/SSE 표현. 실제 content-type과 데이터에 따라 처리하며 payload HTML을 실행하지 않는다.
- 두 요청의 JSON 구조 차이: 경로별 추가/삭제/변경. 원본 보존, 정규화/무시 필드는 명시적으로 표시.
- AI 메시지/tool call/tool result/streaming 등은 원자료를 탐색하는 뷰로 구현. 지원하지 않는 스키마를 억지로 해석하지 않는다.
- 세션 이름·클라이언트·실험 행동·메모 기록. 다른 에이전트/실험 간 비교가 가능하도록 확장.
- 독립 HTML에서도 검색/상세/비교가 동작하고 외부 리소스나 backend에 의존하지 않게 한다.
- 세션 저장과 보고서 내보내기를 구분한다. 원본 포함 내보내기와 축약 내보내기 선택을 명확히 한다.

위 목록은 모두 `web/app.js`에 구현했고 headless Chrome에서 조작해 확인했다. 단, “연결 패킷” 탭은 실제 캡처 데이터로는 아직 확인하지 못했다(macOS BPF 권한 없음). 매칭 방식(endpoint key 기준이며 요청 단위가 아님)은 화면에 문장으로 밝힌다.

## 8. 먼저 점검할 코드 위험과 한계

첫 세션의 검토 후보와 두 번째 세션의 처리 결과다.

1. `capture.cpp`의 Windows `pcap_stat` 직접 선언(필드 3개): **미처리**. Windows에서 Npcap 공식 헤더와 대조해야 한다.
2. h2 `:authority`가 443만 허용하던 문제: **수정**(터널 포트 전달). 비443 테스트 통과.
3. h2 trailer 누락: **수정**(전달 + 기록). HTTP/1 chunked trailer도 기록한다.
4. `Store::evict()`가 pending/streaming flow를 건너뛰어 128 MiB가 엄격한 상한이 아닌 문제: **미처리**.
5. `restore()` 검증: **수정**. session 객체와 중복 packet ID를 검사하고, 실패하면 기존 세션을 유지한다(테스트 있음).
6. TLS 파일 경로와 지문: **수정**. PEM은 `std::filesystem` 경로와 메모리 BIO로 읽고 쓰며, 지문은 DER SHA-256이다(openssl과 일치 확인). Windows Unicode 경로는 미검증.
7. proxy authority 검사: 동작 확인(NUL 포함 9글자 정확). IPv6/잘못된 URI 전용 테스트는 아직 없다.
8. 간접 include: `<memory>`를 `net.hpp`/`packet.hpp`에 명시. 비MSVC 경고 0.
9. sample의 `session.sample`: **수정**(`clear(name, true)`).
10. redact 범위: 변화 없음. UI와 export 대화상자에 “패턴 기반이며 경로·기타 헤더·노트는 남는다”고 표시한다.
11. TCP preview 한계: UI에 “full TCP reassembly가 아니다”라고 표시한다.
12. 압축된 긴 줄 스타일: 아직 그대로다. 학습용으로 함수 경계를 다시 나누는 작업이 남아 있다.
13. 추가 수정: `main.cpp`의 generic lambda `get<>` 컴파일 오류, h2 루프가 양쪽 세션이 끝나도 select를 계속 돌던 문제, CMake가 웹 자산을 재링크 때만 복사하던 문제, deprecated `u8path`.

미구현/지원 보장 불가: HTTP/3·QUIC 복호화, 인증서 pinning 우회, 프록시 비준수 앱 강제 리다이렉션, Windows 파일 I/O hook/드라이버, PID별 완전한 연결 귀속, IP fragment 완전 재조립, WebSocket 메시지 프레임 해석, 모든 압축 본문의 디코딩. 이런 기능을 ‘전체 트래픽을 보고 싶다’라는 장기 목표와 혼동해 완료라고 쓰지 않는다.

## 9. 다음 AI의 실행 순서

1. 이 문서를 읽고 `git status`와 `ctest --test-dir build --output-on-failure`로 현재 상태를 확인한다. 이미 합의한 목표를 다시 묻지 않는다.
2. ~~**Windows 빌드**~~: 완료 — windows 브랜치에서 작업해 2026-10-16 main 에 합침 (vcpkg manifest, MSVC `/W4` 경고 0, `pcap_stat` 헤더 대조). [WINDOWS.md](WINDOWS.md) 참고.
3. **Windows 실제 검증**: 실제 데스크톱에서 Npcap 캡처(loopback 포함), CA 신뢰 설치·삭제(확인 대화상자), Edge + "Use as system proxy" 로 HTTPS·h2 관찰. 결과와 실패를 그대로 기록한다. (러너에서 확인한 범위는 WINDOWS.md 3절)
4. **AI 클라이언트 실험 (키트 준비됨)**: `experiments/001-agent-file-egress/README.md` 절차대로 `make_sandbox.py` → `run_agent.py --label … --task … -- <에이전트 명령>` 을 에이전트마다 실행하고, `summary.txt`·`session.wscope` 를 비교한다. **실제 에이전트 실행은 사용자 계정으로 외부 서비스에 요청이 나가므로 사용자 확인 후에만.** 결과는 관찰로만 쓴다(한 번의 관찰을 "항상"으로 일반화하지 않음).
4-1. provenance 다음 후보: 파일 I/O 추적(macOS `fs_usage`, Windows ETW/Process Monitor)을 시간·PID 로 provenance 결과와 맞추기 — "어느 프로세스가 읽었나"까지. 의미 유사도 판정은 판단 문장이 생기므로 하지 않기로 했다.
5. `Store` 메모리 상한(4번), proxy authority 엣지 케이스 테스트, 학습용 코드 포맷 정리.
6. CI: Windows 는 `.github/workflows/windows.yml` (MSVC 빌드 + 전체 ctest). macOS/Linux job 은 아직 없다. GitHub 로그는 로그인해야 받을 수 있어서 결과는 annotation 으로도 남긴다 (`.github/ci_annotate.py`).

현재 호스트 참고: cmake `/opt/homebrew/bin/cmake`, OpenSSL `/opt/homebrew/opt/openssl`, nghttp2 `/opt/homebrew/opt/libnghttp2`, `nghttpd`는 `/opt/homebrew/opt/nghttp2/bin`에 있다(PATH에는 없지만 CMake가 HINTS로 찾는다). macOS에서 live 캡처는 `/dev/bpf*` 권한이 없어 동작하지 않는다(Mac은 목표 OS가 아니다).

```sh
cmake -S . -B build -DCMAKE_PREFIX_PATH="/opt/homebrew/opt/openssl;/opt/homebrew/opt/libnghttp2"
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## 10. 이어받을 때 사용할 짧은 프롬프트

> /Users/andy6609/projects/Andy-fiddler/docs/AI-HANDOFF.md를 읽고 WireScope를 이어가줘. Windows용 C++ 네트워크 관찰 도구이고, 엔진·UI·테스트는 macOS 개발 호스트에서 검증됐지만 Windows 빌드·Npcap·인증서 신뢰·실제 AI 클라이언트 실험은 아직이야. 새 기획 질문부터 하지 말고 ctest로 상태를 확인한 뒤 9절 순서대로 진행해줘. ‘파일 전송으로 판단했습니다’ 같은 해설 문구는 넣지 말고 관찰한 원자료를 보여줘. 구현한 것과 검증한 것을 구분해 보고해줘.
