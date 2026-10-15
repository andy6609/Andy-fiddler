# 참고 오픈소스와 WireScope에 반영한 특징

작성/링크 재확인: 2026-10-15.

이 문서는 앞선 대화에서 검토한 프로젝트와 채택 방향을 기록한다. **아이디어 참고, 실제 라이브러리 사용, 앞으로 구현할 기능을 구분한다.** 아래 도구들을 결합하거나 그 엔진을 가져와 완성품을 만든 상태가 아니다. 기능 설명은 공식 저장소/문서를 기준으로 하며 향후 버전에 따라 바뀔 수 있다.

## 1. 전체 비교

| 참고 대상 | 살펴본 특징 | WireScope에 가져올 부분 | 현재 반영 정도 |
|---|---|---|---|
| [mitmproxy](https://github.com/mitmproxy/mitmproxy), [Flow API](https://docs.mitmproxy.org/stable/api/mitmproxy/flow.html) | 요청 하나를 flow로 다루며 client/server 연결, 오류와 메타데이터를 함께 보관 | Flow 중심 기록, 연결과 요청 분리, 오류와 타임라인 보존 | 자체 Flow/Store와 연결 메타데이터 초안 있음. mitmproxy 엔진은 사용하지 않음 |
| [HTTP Toolkit](https://github.com/httptoolkit/httptoolkit) | HTTP(S) 디버깅 도구, 요청 목록에서 상세를 조사하는 UI 참고 | 목록과 inspector를 오가며 headers/body/timing을 확인하는 구성 | 3열 검사 화면(`web/app.js`) 구현 |
| [PcapPlusPlus](https://github.com/seladb/PcapPlusPlus) | C++ 패킷 캡처·파싱·작성, 다양한 캡처 backend와 TCP 재조립 기능 | packet → protocol fields → byte offsets, TCP stream을 관찰하는 계층 구조 | 실제 의존성으로 넣지 않음. 현재 자체 parser + Npcap 직접 연동 초안. 재조립을 강화할 때 재평가할 후보 |
| [CodingAgentExplorer](https://github.com/tndata/CodingAgentExplorer) | .NET 기반 AI 요청 검사, HTTP headers/body, SSE, conversation 및 MCP 관찰 화면 | AI 요청도 일반 HTTP 증거 위에서 분석, streaming과 tool 관련 구조 탐색 | SSE 이벤트 뷰, 필드 join, messages/contents/input 구조 뷰 구현. MCP/hook 연동은 미구현 |
| [claude-tap](https://github.com/liaohch3/claude-tap), [README](https://github.com/liaohch3/claude-tap/blob/main/README.md) | 여러 코딩 에이전트의 트래픽 관찰, prompt diff, 외부 의존성 없는 HTML 뷰어 내보내기 | **요청 간 구조 비교, 여러 에이전트 비교 실험, 독립 HTML 보고서** | 사용자가 특히 좋아한 방향. JSON path diff, side-by-side diff, 독립 HTML 오프라인 뷰어 구현 |
| [ProxyPin](https://github.com/wanghongenpin/proxypin) | 여러 플랫폼에서 HTTP(S) 캡처·검사·rewrite를 제공하는 Flutter 앱 | 캡처/검색/상세 탐색의 실용적인 도구 구성 참고 | 전반적 UX 참고. Flutter·멀티플랫폼·rewrite 기능은 채택하지 않음 |

이 표에서 ‘가져온다’는 프로젝트 목적에 맞게 재해석한 설계 방향이다. 각 원본 소스의 특정 함수나 알고리즘을 포팅했다는 뜻이 아니다. 줄 단위 코드 포팅을 새로 한다면 해당 커밋·파일·라이선스를 별도로 기록해야 한다.

## 2. 각 아이디어가 우리 목적과 연결되는 방식

### mitmproxy → 관찰 단위와 근거의 보존

한 요청을 headers/body만으로 끝내지 않고 연결·타이밍·오류와 함께 보관한다. WireScope의 자체 `Flow`가 이 방향을 따른다. 사용자에게 자연어 결론을 주는 것보다 상세 기록을 다시 열어 무엇을 실제로 봤는지 확인하게 한다.

반영 위치: `src/core.hpp`, `src/core.cpp`, `src/proxy.cpp`, `src/http2.cpp`, `web/app.js`. 현재 모델이 mitmproxy와 호환되거나 mitmproxy 캡처 파일을 읽는 것은 아니다.

### HTTP Toolkit / ProxyPin → 매일 쓸 수 있는 검사 화면

단순 콘솔 로그를 넘어 요청 테이블, 검색, 선택한 항목의 상세를 빠르게 오갈 수 있는 UI를 참고했다. 우리 화면은 요청에서 패킷/바이트로 더 내려가야 한다. 요청 행에서 같은 연결의 패킷으로, 패킷 필드에서 바이트 위치로 이동할 수 있다.

### PcapPlusPlus → 하위 계층과 스트림

C++로 패킷 계층을 탐색하고 TCP 데이터를 연결 관점에서 다루는 참고 대상이다. 현재는 Npcap DLL을 직접 사용하는 캡처 코드와 자체 디코더를 작성했다. 따라서 PcapPlusPlus의 재조립 안정성이나 프로토콜 지원 폭을 현재 코드의 장점으로 주장하면 안 된다.

향후 직접 구현을 유지할지 라이브러리를 쓸지는 학습 목표, 재조립 정확도, 개발 시간으로 판단한다. ‘바닥부터 공부한다’가 암호·TLS·HTTP/2 라이브러리까지 모두 다시 작성한다는 뜻은 아니다.

### CodingAgentExplorer → 일반 HTTP에서 AI 의미 구조까지

HTTP 증거를 유지하면서 SSE 이벤트와 AI 요청 안의 메시지·tool call 같은 구조를 별도로 살펴보는 아이디어다. 모든 AI 클라이언트를 동일한 형식으로 뭉개지 않는다. 지원하는 스키마만 해석하고 원문을 언제든 확인하도록 한다.

현재 계획은 WireScope 자체 UI에 이런 탐색을 추가하는 것이다. CodingAgentExplorer의 .NET/YARP/SignalR, hook collector, MCP 전용 프록시를 들여온 것은 아니다.

### claude-tap → 비교와 재현 가능한 공유

사용자가 요청 간 구조 비교와 독립 HTML 내보내기를 명시적으로 긍정했다. 같은 작업을 여러 에이전트/클라이언트에서 실행하고 요청 형태·본문 변화·streaming 차이를 비교할 수 있도록 한다.

비교는 ‘어느 서비스가 더 좋다’ 같은 자동 평가가 아니라 JSON 경로별 추가/삭제/변경, 헤더와 요청 순서, body 크기 등 관측 가능한 차이를 보여주는 방향이다. 세션에는 클라이언트/행동/메모를 남긴다. 서버 없이 열리는 HTML에서도 상세와 비교를 유지하려고 로컬 웹 UI 방식을 택했다.

`htmlReport()`가 데이터와 `app.js`를 한 파일에 넣고, `app.js`는 오프라인 모드에서 검색·상세·비교를 그대로 제공한다. 실제 에이전트 트래픽으로 만든 보고서는 아직 없다.

## 3. 실제로 사용하는 코드/라이브러리

아래는 아이디어 참고 목록과 다르다.

| 항목 | 역할 | 현재 형태 |
|---|---|---|
| [cpp-httplib](https://github.com/yhirose/cpp-httplib) | 로컬 UI HTTP 서버와 API | v0.61.0 단일 헤더를 `third_party/httplib.h`에 저장, LICENSE 포함 |
| [nlohmann/json](https://github.com/nlohmann/json) | JSON 데이터 모델·직렬화 | v3.11.3 단일 헤더를 `third_party/json.hpp`에 저장, LICENSE 포함 |
| [OpenSSL](https://github.com/openssl/openssl) | TLS, CA/leaf 인증서, 해시 등 | CMake 외부 의존성. vendoring하지 않음 |
| [nghttp2](https://github.com/nghttp2/nghttp2) | HTTP/2 세션/프레임 및 스트림 중계 | CMake 외부 의존성. 자체 bridge에서 API 사용 |
| [Npcap](https://npcap.com/) | Windows 패킷 캡처 | 사용자 환경의 DLL 동적 로드. SDK/드라이버를 저장소에 포함하지 않음 |

Npcap은 위의 오픈소스 참고 도구들과 라이선스/배포 조건을 동일하게 취급하지 않는다. 설치 및 재배포 조건은 패키징 전에 공식 문서에서 확인한다. 현재 배포물이나 설치 프로그램은 없다.

## 4. 합쳐진 제품 방향

```text
mitmproxy의 flow 관점
 + HTTP Toolkit / ProxyPin의 검사 UI 관점
 + PcapPlusPlus에서 참고한 패킷/스트림 계층 관점
 + CodingAgentExplorer의 AI 요청/SSE 탐색 관점
 + claude-tap의 구조 비교 / 독립 HTML 관점
 = WireScope: 요청에서 패킷과 바이트로 내려가는 관찰 도구
```

이 식은 방향 설명이다. 라이브러리 의존 그래프가 아니다.

Fiddler와 Wireshark는 사용자가 떠올린 경험과 탐색 방식의 기준이다. 두 제품을 완전히 복제하거나 각각의 기능을 전부 제공한다는 약속이 아니다. 특히 ‘패킷이 보인다’, ‘TLS 평문이 보인다’, ‘파일의 로컬 I/O가 보인다’는 서로 다른 수집 능력이다. 이 경계를 UI에 사실대로 드러내면서 연결해 보는 것이 핵심이다.

## 5. 다음 조사 때 기록할 것

새 라이브러리나 특정 구현을 실제로 가져오면 프로젝트 URL만 적지 말고 버전/커밋, 파일, 라이선스, 채택 이유, 현재 코드와 연결되는 위치를 기록한다. AI 서비스 실험에는 날짜·OS·클라이언트 버전·실행 방식·동작·헤더/메서드·캡처 범위와 누락을 함께 기록한다. 서비스명만으로 업로드 방식이나 프로토콜을 일반화하지 않는다.
