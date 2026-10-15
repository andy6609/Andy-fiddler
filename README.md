# WireScope

**요청 하나를, 그 요청을 실어 나른 패킷의 바이트까지.**

WireScope는 C++20으로 만든 cross-layer 트래픽 관찰 도구입니다. 프록시가 기록한 HTTP 요청(L7)에서 출발해, 그 요청이 오간 TCP 연결(L4)과 그 연결을 이루는 IP 패킷(L3), 각 필드의 바이트 위치(L2)까지 한 화면에서 따라 내려갈 수 있습니다.

> 저장소 이름 `Andy-fiddler`는 시작점(Fiddler 같은 검사 창을 직접 만들어 보기)을, 제품 이름 `WireScope`는 도착점(선 위의 바이트까지 들여다보기)을 뜻합니다.

![요청 inspector](docs/images/inspector-request.png)

---

## Cross-layer: Fiddler와 Wireshark 사이

네트워크는 계층으로 나뉘어 있고, 대부분의 도구는 한 계층을 중심으로 봅니다.

- **Fiddler**는 애플리케이션 계층(L7)을 봅니다. 요청과 응답 내용은 잘 보이지만, 그 요청이 어떤 패킷으로 오갔는지는 보이지 않습니다.
- **Wireshark**는 패킷 단위로 여러 계층의 헤더를 보여줍니다. 하지만 TLS로 암호화된 HTTP 내용은 세션 키 로그가 없으면 볼 수 없습니다.

WireScope는 이 둘 사이의 끊긴 지점을 잇습니다.

```
 L7  HTTP    POST /v1/messages · 헤더 · body · HTTP/2 stream 5     ← 프록시가 TLS를 종단해 평문으로 기록
              │
              │  연결 key  127.0.0.1:53211 | 127.0.0.1:18080
              ▼
 L4  TCP     연결 하나 · SYN → … → FIN · seq/ack · 방향별 바이트 흐름 (빠진 구간은 GAP)
              │
              ▼
 L3  IP      그 연결을 이룬 패킷들 · src/dst · TTL · 길이
              │
              ▼
 L2  bytes   02 02 02 … 08 00 45 00 …    필드 ↔ 바이트 오프셋을 서로 강조
```

|  | Fiddler | Wireshark | WireScope |
|---|---|---|---|
| 중심 계층 | L7 | L2 ~ L7 (패킷 단위) | L7 → L2를 이어서 |
| HTTPS 내용 | 프록시 CA로 복호화 | 세션 키 로그가 있으면 복호화 | 프록시 CA로 복호화 |
| 요청 → 패킷 | 보이지 않음 | 패킷은 보이지만 요청과 직접 이어지지 않음 | 같은 연결 key로 이동 |
| 패킷 → 바이트 | — | 필드별 바이트 강조 | 필드별 바이트 강조 |

요청과 패킷은 **연결 단위**로 이어집니다. 한 TCP 연결에 여러 요청이 실릴 수 있으므로(keep-alive, HTTP/2 다중화) "이 패킷이 이 요청"이라는 일대일 대응은 아닙니다. 이 경계는 화면에도 그대로 적어 둡니다.

<details>
<summary>용어 메모 — "cross-layer design"</summary>

네트워크 분야에서 *cross-layer design*은 원래 계층 사이에 정보를 공유해 성능을 높이는 설계를 가리킵니다. 예를 들어 무선 환경에서 물리 계층의 채널 상태를 전송 계층이 참고하는 식입니다. WireScope의 cross-layer는 **분석 관점**의 말입니다. 계층을 건드리는 게 아니라, 한 요청을 계층을 가로질러 따라가며 본다는 뜻입니다. 계층 간 정보를 하나로 묶어 본다는 점에서 의미가 자연스럽게 이어집니다.
</details>

---

## 왜 만들었나

인턴십에서 AI 서비스가 파일과 데이터를 네트워크로 어떻게 옮기는지 관찰하는 PoC를 했습니다. 마지막 날 멘토님이 "Fiddler로 흐름을 봤으면, 다음엔 검사 창을 직접 만들어 봐라"라고 조언했고, 그게 시작입니다. 목표는 프록시가 실제로 무엇을 하는지, 패킷이 어떻게 오가는지를 세포 단위까지 직접 확인하는 것입니다.

중요한 조사 대상은 여러 AI 서비스와 코딩 에이전트입니다. 같은 작업을 서로 다른 클라이언트로 실행하고, 요청을 구조 단위로 비교하고, 서버 없이 열리는 HTML 보고서로 남기는 흐름을 지원합니다.

---

## 무엇을 볼 수 있나

| 수준 | 대상 |
|---|---|
| **내용까지** | HTTP/1.x, HTTP/2: 메서드, 헤더(순서 유지), body, 스트림, trailer, 타이밍. HTTPS는 TLS 종단 시 |
| **구조와 바이트까지** | TCP · UDP · ICMP · ARP · IPv4/IPv6 헤더 필드, DNS 질의, TLS 레코드, TLS 통과 터널, WebSocket 업그레이드 이후 바이트, 프록시를 무시하는 앱의 트래픽 |
| **볼 수 없음** | QUIC/HTTP3 내용, 인증서 고정(pinning) 앱의 내용, 비-HTTP 프로토콜의 의미 해석, 보낸 프로세스(PID), 로컬 파일 I/O |

조건부 항목, 보관 한도, 항목별 이유와 대안은 [**관찰 범위 보고서**](docs/COVERAGE.md)에 정리했습니다.

---

## 둘러보기

**패킷 필드 ↔ 바이트.** 필드를 누르면 해당 바이트가 강조되고(그림은 `TCP flags`, offset 47), 바이트를 누르면 그 바이트를 포함하는 가장 좁은 필드가 선택됩니다.

![패킷 필드와 바이트](docs/images/packet-fields.png)

**두 요청 비교.** JSON 잎 경로 단위 비교와 side-by-side 줄 비교를 제공합니다. 무시한 경로와 키 정렬 같은 정규화는 숨기지 않고 화면 위에 표시합니다.

![요청 비교](docs/images/compare.png)

<sub>스크린샷 데이터: curl → WireScope → 로컬 테스트 서버(HTTP/1.1·HTTPS·HTTP/2)로 보낸 실제 요청, 그리고 합성 pcap. 실제 AI 서비스 트래픽은 아닙니다.</sub>

---

## 기능

- **프록시** (`127.0.0.1:18080`): HTTP/1.x, CONNECT, 로컬 CA로 TLS 종단(host별 인증서 즉석 발급, 업스트림 인증서 검증), HTTP/2 다중 스트림 중계(nghttp2 세션 2개), chunked·trailer, WebSocket 업그레이드 터널, TLS 통과 모드
- **패킷**: Npcap 라이브 캡처(DLL 런타임 로드, BPF 필터), Ethernet ~ DNS/TLS 디코딩과 필드별 바이트 오프셋, pcap/pcapng 가져오기·내보내기, TCP 스트림 미리보기(GAP 표시)
- **검사 화면** (`127.0.0.1:17890`): 요청 → headers / body(JSON · Text · Hex · SSE · messages 구조) / timeline / 같은 연결의 패킷. gzip/deflate 디코딩, 1 MiB 캡처 한도와 잘림 표시
- **비교와 기록**: 구조적 JSON diff, 세션 메타데이터(클라이언트 · 실험 행동 · 메모), 요청별 노트
- **내보내기**: `.wscope` 세션, `.pcapng`, 단일 파일 HTML 보고서(오프라인 뷰어 포함, 패턴 기반 redact 옵션)
- **로컬 API 보안**: 실행별 토큰, Host 검사(DNS 리바인딩), Origin 검사(교차 출처 요청), CSP

### 원칙

1. **판단 대신 원자료.** "파일 전송으로 판단했습니다" 같은 문장을 쓰지 않습니다. 헤더, 바이트, 타이밍, 연결을 보여주고 해석은 사람이 합니다.
2. **모르는 건 모른다고.** 잘린 body는 `captured / total`로, 캡처가 놓친 구간은 `GAP n bytes`로 표시합니다. 추측으로 채우지 않습니다.
3. **정규화는 드러낸다.** 비교에서 무시한 경로는 개수와 패턴을 함께 표시합니다.

---

## 빌드와 실행

필요한 것: CMake ≥ 3.20, C++20 컴파일러, OpenSSL 3, nghttp2. Windows에서 캡처하려면 [Npcap](https://npcap.com/)(loopback 지원 옵션)이 필요합니다.

```sh
# macOS 개발 호스트 예시 (Homebrew)
cmake -S . -B build -DCMAKE_PREFIX_PATH="/opt/homebrew/opt/openssl;/opt/homebrew/opt/libnghttp2"
cmake --build build -j
ctest --test-dir build --output-on-failure   # 단위 + end-to-end + lab
./build/WireScope --sample                   # 합성 샘플로 시작 → http://127.0.0.1:17890
```

옵션: `--port N`(UI 포트), `--data DIR`(CA 저장 위치, Windows 기본 `%LOCALAPPDATA%\WireScope`), `--web DIR`, `--no-open`, `--sample`.

클라이언트 연결 방법(프록시 변수, `NODE_EXTRA_CA_CERTS`, curl `--cacert`)은 화면의 **Certificate → Client setup**에 있습니다. WireScope는 시스템 프록시 설정을 바꾸지 않습니다.

---

## 현재 상태

| 항목 | 상태 |
|---|---|
| macOS 빌드, 단위 테스트(94개 검증 항목), end-to-end 테스트(46개 검증 항목: 로컬 HTTP·HTTPS·HTTP/2 서버 대상) | 통과 (2026-10-15) |
| lab v1 ~ v8 스모크 테스트(86개 검증 항목) | 통과. v6 라이브 캡처는 권한 문제로 에러 경로만 확인 |
| headless Chrome으로 화면 조작(목록, 상세, SSE, gzip, 비교, 패킷 hex, 오프라인 보고서) | JS 오류 없음 |
| Windows 빌드, Npcap 실제 캡처, Windows 인증서 저장소 신뢰 설치 | **미검증** |
| 실제 AI 서비스·코딩 에이전트 트래픽 관찰 | **미수행** |

---

## lab/ — 개념별 학습 버전

WireScope에 들어간 개념을 버전 하나에 하나씩 떼어 만든 실행 파일들입니다. 한국어 주석과 버전별 노트가 함께 있습니다.

| 프록시 안에서 | 선 위에서 | 보여주기 |
|---|---|---|
| v1 기록 단위와 body 한도 | v4 패킷 → 필드 오프셋 | v7 엔진 ↔ 브라우저, 보안 경계 |
| v2 TLS 통과 vs 종단 | v5 패킷 → TCP 바이트 흐름, GAP | v8 구조 비교, 독립 HTML |
| v3 HTTP/2 프레임과 HPACK | v6 libpcap/Npcap, BPF | |

로드맵과 각 버전이 본체 어디에 해당하는지는 [docs/lab/README.md](docs/lab/README.md)에 있습니다.

---

## 문서와 코드 읽는 순서

| 문서 | 내용 |
|---|---|
| [docs/COVERAGE.md](docs/COVERAGE.md) | 볼 수 있는 것 / 조건부 / 볼 수 없는 것, 검증 상태 |
| [docs/lab/README.md](docs/lab/README.md) | lab 로드맵과 버전별 노트 |
| [docs/AI-HANDOFF.md](docs/AI-HANDOFF.md) | 맥락, 설계 결정, 남은 작업 |
| [docs/OPEN-SOURCE-REFERENCES.md](docs/OPEN-SOURCE-REFERENCES.md) | 참고한 오픈소스와 실제 의존성 |

1. `src/core.hpp` / `core.cpp`: Flow · Packet · Store 데이터 모델, 세션 저장·복원, 보고서
2. `src/proxy.cpp`: HTTP/1, CONNECT, TLS 종단
3. `src/http2.cpp`: 클라이언트 쪽과 업스트림 쪽 nghttp2 세션 사이의 스트림 중계
4. `src/packet.cpp`, `src/capture.cpp`: 패킷 디코딩과 Npcap 캡처
5. `src/main.cpp`: 로컬 API와 보안 경계
6. `web/app.js`: 실시간 모드와 오프라인 보고서 모드가 함께 쓰는 검사 화면
7. `tests/`: `core_tests.cpp`, `integration_test.py`, `lab_smoke.py`

기술 스택: C++20 · OpenSSL · nghttp2 · libpcap/Npcap · cpp-httplib · nlohmann/json · JavaScript(프레임워크 없음) · CMake/CTest
