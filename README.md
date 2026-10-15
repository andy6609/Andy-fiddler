# Andy-fiddler (WireScope)

멘토님의 조언("Fiddler로 흐름을 보고, 다음엔 검사 창을 직접 만들어 봐라")을 계기로, 프록시와 네트워크 통신을 더 깊이 이해하려고 만드는 Windows용 C++ 관찰 도구입니다. 연결·요청에서 시작해 프로토콜 구조와 실제 바이트까지 내려가 확인하고, 관측 결과를 비교·보관해 설명할 수 있게 하는 것이 목표입니다.

AI 서비스와 여러 코딩 에이전트는 이 도구로 조사할 중요한 대상입니다. 같은 작업을 서로 다른 클라이언트로 실행하고, 요청 간 구조 차이를 비교하고, 서버 없이 열리는 독립 HTML 보고서로 남길 수 있습니다. 화면은 "파일 전송으로 판단했습니다" 같은 해설 대신 헤더, 메서드, 바이트, 타이밍, 스트림, 연결 같은 원자료와 탐색 도구를 보여줍니다.

## 할 수 있는 것

- **명시적 프록시** (기본 `127.0.0.1:18080`): HTTP/1.x, CONNECT, 로컬 CA로 TLS를 종단하는 HTTPS 기록, HTTP/2 다중 스트림 중계(nghttp2), chunked·trailer, WebSocket 업그레이드 터널. TLS를 종단하지 않는 passthrough 모드도 있습니다.
- **패킷 캡처**: Windows Npcap(DLL 동적 로드), Ethernet/VLAN/IPv4/IPv6/TCP/UDP/DNS/TLS 레코드 필드를 바이트 offset과 함께 기록, pcap/pcapng 가져오기·내보내기, TCP 스트림 미리보기(gap 표시)
- **검사 UI** (`http://127.0.0.1:17890`)
  - 요청 목록 → headers / body(JSON, Text, Hex, SSE events, messages 구조) / timeline / 같은 연결의 패킷
  - gzip/deflate 본문 디코딩 토글, 1 MiB 캡처 한도와 잘림 표시, 캡처한 바이트의 sha256
  - 패킷 필드에 마우스를 올리면 해당 바이트 강조, 바이트를 누르면 그 바이트를 포함하는 필드 강조
  - **두 요청 비교**: JSON leaf path별 추가·삭제·변경, side-by-side line diff, 무시할 경로(`messages[*].content` 등)와 key 정렬을 명시적으로 표시
  - 세션 메타데이터(클라이언트, 실험 행동, 메모)와 요청별 노트
- **내보내기**: `.wscope` 세션(다시 가져오기 가능), `.pcapng`, 독립 HTML 보고서(뷰어와 데이터가 한 파일에 들어 있으며, 본문·패킷·자격 증명 헤더·query를 지우는 redact 옵션 제공)

## 빌드와 실행

필요한 것: CMake ≥ 3.20, C++20 컴파일러, OpenSSL 3, nghttp2. Windows에서 캡처하려면 [Npcap](https://npcap.com/)이 설치되어 있어야 합니다.

```sh
# macOS 개발 호스트 예시 (Homebrew)
cmake -S . -B build -DCMAKE_PREFIX_PATH="/opt/homebrew/opt/openssl;/opt/homebrew/opt/libnghttp2"
cmake --build build -j
ctest --test-dir build --output-on-failure   # 단위 테스트 + 프록시 end-to-end 테스트
./build/WireScope --sample                   # 합성 샘플을 넣고 시작, 브라우저에서 http://127.0.0.1:17890
```

옵션: `--port N`(UI 포트), `--data DIR`(CA 저장 위치. Windows 기본값은 `%LOCALAPPDATA%\WireScope`), `--web DIR`, `--no-open`, `--sample`.

클라이언트 연결 방법(프록시 변수, `NODE_EXTRA_CA_CERTS`, curl `--cacert`)은 UI의 **Certificate → Client setup**에 나옵니다. WireScope는 시스템 프록시 설정을 바꾸지 않습니다.

## 현재 상태

| 항목 | 상태 |
|---|---|
| macOS 호스트에서 빌드·단위 테스트(94개 검사)·end-to-end 테스트(46개 검사) | 통과 (2026-10-15) |
| lab v1~v8 스모크 테스트(86개 검사) | 통과. 단 v6 라이브 캡처는 권한 문제로 에러 경로만 확인 |
| headless Chrome으로 UI 실제 조작(목록, 상세, SSE, gzip, 비교, 패킷 hex, 오프라인 보고서) | JS 오류 없이 동작 확인 |
| Windows 빌드, Npcap 실제 캡처, Windows 인증서 저장소 신뢰 설치 | **미검증** |
| 실제 AI 서비스·코딩 에이전트 트래픽 관찰 | **미수행** |

관찰 가능한 범위와 한계는 [관찰 범위 보고서](docs/COVERAGE.md)에, 자세한 맥락, 설계, 남은 작업은 [AI 인수인계 문서](docs/AI-HANDOFF.md)에, 참고한 오픈소스와 실제 의존성의 구분은 [OPEN-SOURCE-REFERENCES](docs/OPEN-SOURCE-REFERENCES.md)에 있습니다.

## lab/ — 개념별 학습 버전

local-proxy-lab 에서 `proxy_v1 → v4` 로 쌓아 올렸던 것처럼, WireScope 에 들어간 개념을 버전 하나에 하나씩 떼어 만든 실행 파일들이 `lab/` 에 있습니다 (한국어 주석, 버전별 노트).

| | |
|---|---|
| v1 flow_recorder → v2 tls_recorder → v3 h2_observer | 프록시 안에서: 기록 단위, HTTPS passthrough/MITM, h2 프레임과 HPACK |
| v4 packet_decoder → v5 tcp_stream → v6 live_capture | 선 위에서: 필드 offset, TCP 재조립과 GAP, libpcap/BPF |
| v7 inspector_api → v8 diff_report | 보여주기: 엔진↔브라우저와 보안 경계, 구조 비교와 독립 HTML |

로드맵과 각 버전이 본체 어디에 해당하는지는 [docs/lab/README.md](docs/lab/README.md)에 있습니다. 위에서 아래로 공부하다가 막히는 개념이 있으면 해당 lab 버전으로 내려가서 보면 됩니다.

## 코드 읽는 순서

1. `src/core.hpp` / `core.cpp`: Flow·Packet·Store 데이터 모델, 세션 저장·복원, 보고서
2. `src/proxy.cpp`: HTTP/1, CONNECT, TLS 종단
3. `src/http2.cpp`: 클라이언트와 업스트림 두 nghttp2 세션 사이의 스트림 중계
4. `src/packet.cpp`, `src/capture.cpp`: 패킷 디코딩과 Npcap 캡처
5. `src/main.cpp`: 로컬 API와 보안 경계(token, Host, Origin)
6. `web/app.js`: 실시간 모드와 오프라인 보고서 모드가 함께 쓰는 검사 UI
7. `tests/`: `core_tests.cpp`(소켓 없는 단위 테스트), `integration_test.py`(curl → 프록시 → 로컬 HTTP/HTTPS/h2 서버), `lab_smoke.py`(lab 버전들)

기존 인턴 프로젝트(`../local-proxy-lab/proxy_ToInfinity/`, `../local-proxy-lab/Infinity_v2/`)는 별도로 보존합니다.
