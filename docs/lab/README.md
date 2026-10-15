# lab/ — WireScope 를 개념 하나씩 떼어 만든 버전들

> local-proxy-lab 에서 `proxy_v1 → v4`, `pure_m1~m3` 로 프록시를 쌓았던 것처럼,
> WireScope 에 들어간 개념을 **버전 하나에 하나씩** 따로 만들어 본 것.
> 각 버전은 `.cpp` 하나 + 공용 헤더(`lab/common/lab_net.hpp`)이고, 본체(`src/`)와 코드를 섞지 않는다.

---

## 로드맵

```
 프록시 안에서 보기                        선 위에서 보기                     보여주기
 ───────────────────                       ──────────────                     ─────────
 v1 flow_recorder   중계 → 기록(JSONL)     v4 packet_decoder  패킷 → 필드/offset   v7 inspector_api  엔진 ↔ 브라우저, 보안 경계
 v2 tls_recorder    passthrough / MITM     v5 tcp_stream      패킷 → 연결/바이트   v8 diff_report    두 요청 비교, 독립 HTML
 v3 h2_observer     h2 프레임, HPACK       v6 live_capture    libpcap/Npcap, BPF
          │                                        │                                   │
          └──────────────── 같은 연결 key (정렬한 endpoint 쌍) 로 이어짐 ─────────────┘
                                                   ▼
                                        WireScope 본체 (src/ + web/)

 Windows 에서만 (windows 브랜치)
 ───────────────────────────────
 v9  win_owner      연결 → 프로세스 (TCP 연결 표의 owning PID)
 v10 win_sysproxy   시스템 프록시가 세 군데인 이유 (WinINET / WinHTTP / 환경 변수)
```

| 버전 | 핵심 질문 | 본체에서 해당하는 곳 | 노트 |
|---|---|---|---|
| v1 | 지나가는 요청을 어떤 단위로 남기나? body 가 크면? | `core.cpp` Flow/Body, `proxy.cpp` relayBody | [v1](v1-notes.md) |
| v2 | HTTPS 를 안 풀면 뭐가 보이고, 풀면 뭐가 필요한가? | `tls.cpp`, `proxy.cpp` CONNECT/MITM | [v2](v2-notes.md) |
| v3 | h2 는 어떻게 생겼고 헤더는 왜 그냥 안 읽히나? | `http2.cpp` (bridge 방식) | [v3](v3-notes.md) |
| v4 | 바이트 하나하나가 어느 층의 무슨 필드인가? | `packet.cpp` decodePacket, UI Fields & bytes | [v4](v4-notes.md) |
| v5 | 조각난 패킷을 어떻게 다시 흐름으로? 빠진 건? | `packet.cpp` streamPreview, UI TCP stream | [v5](v5-notes.md) |
| v6 | 파일 말고 지금 선 위에서 잡으려면? | `capture.cpp` | [v6](v6-notes.md) |
| v7 | 화면은 엔진과 어떻게 대화하고, 무엇을 막아야 하나? | `main.cpp` API, `web/app.js` polling | [v7](v7-notes.md) |
| v8 | 두 요청의 차이를 판단 없이 어떻게 보여주나? | `web/app.js` Compare, `core.cpp` htmlReport | [v8](v8-notes.md) |
| v9 | 이 연결은 어느 프로세스가 열었나? (Windows) | `process.cpp`, UI Process 열 | [v9](v9-notes.md) |
| v10 | 시스템 프록시를 켜면 누가 따르고 누가 안 따르나? (Windows) | `sysproxy.cpp`, UI "Use as system proxy" | [v10](v10-notes.md) |

---

## 빌드와 실행

```sh
cmake -S . -B build -DCMAKE_PREFIX_PATH="/opt/homebrew/opt/openssl;/opt/homebrew/opt/libnghttp2"   # WIRESCOPE_BUILD_LAB=ON 이 기본
cmake --build build -j
ls build/lab/                                     # v1_flow_recorder ... v8_diff_report
python3 tests/lab_smoke.py build                  # 버전별 스모크 테스트 (ctest 에도 lab 으로 들어 있음)
```

Windows (PowerShell, `windows` 브랜치):
```powershell
.\scripts\build-windows.ps1 -Test all          # 본체 + lab 빌드, core/integration/lab/windows 테스트 (pip install h2 필요)
dir build-windows\lab\                          # v1_flow_recorder.exe ... v10_win_sysproxy.exe (v6 은 Npcap SDK 가 있을 때만)
build-windows\lab\v9_win_owner.exe --self
build-windows\lab\v10_win_sysproxy.exe
```

포트: v1 `18081`, v2 `18082`, v3 `18083`, v7 UI `18087`. 본체(UI 17890, 프록시 18080)와 겹치지 않게 따로 잡았다.

이어서 써 보는 예:
```sh
./build/lab/v1_flow_recorder flows.jsonl &                 # 프록시 + 기록
./build/lab/v7_inspector_api flows.jsonl &                 # 같은 파일을 브라우저로 http://127.0.0.1:18087/
curl -x http://127.0.0.1:18081 -d '{"a":1}' http://127.0.0.1:8000/x
curl -x http://127.0.0.1:18081 -d '{"a":2,"b":true}' http://127.0.0.1:8000/x
./build/lab/v8_diff_report flows.jsonl 1 2 --report diff.html
```

---

## 공통 규칙 (본체와 같음)

1. **판단 문장 금지.** "파일 업로드로 판단" 같은 출력 없음. 필드, 바이트, 시간, 개수만.
2. **모르는 건 모른다고.** 잘린 body 는 `captured/total`, 캡처 구멍은 `GAP n bytes`, 해석이 멈추면 멈춘 이유.
3. **정규화는 드러낸다.** diff 에서 무시한 경로는 개수와 패턴을 출력에 남긴다.
4. **검증한 것과 안 한 것을 나눈다.** 각 노트 마지막 절. Windows 는 GitHub Actions 러너에서 돌린 결과만 "확인"으로 쓴다 ([WINDOWS.md](../WINDOWS.md)). 라이브 캡처는 아직 어디서도 못 돌려봤다.

---

## 확인 상태 (2026-10-16)

macOS = 개발 호스트, Windows = GitHub Actions `windows-latest` 러너 (MSVC). 둘 다 `tests/lab_smoke.py` 88개 검사 통과.

| 버전 | 스모크 테스트 | Windows 에서 걸렸던 것 ([WINDOWS.md](../WINDOWS.md) 5절) | 못 해본 것 |
|---|---|---|---|
| v1~v3 | curl/nghttpd(또는 Python h2 서버) 로컬 서버 대상 통과 | `setvbuf(_IOLBF, 0)` 즉시 종료, OpenSSL 에 `FILE*`, 인증서 거부가 `SSL_accept` 뒤에 옴 | 실제 서비스/에이전트 |
| v4~v5 | 합성 pcap/pcapng 통과 | v5: 텍스트 모드 stdout 이 `\r\n` 을 `\r\r\n` 으로 | 실제 캡처 파일 |
| v6 | 파일 재생 + BPF, 권한 없을 때 에러 경로 (macOS) | Windows 는 Npcap SDK 가 없어 빌드에서 빠짐 | **라이브 캡처 자체**, Windows Npcap |
| v7 | 보안 403 3종, 브라우저 화면(headless Chrome) | — | — |
| v8 | diff, 보고서 escape/redact | (테스트 쪽 인코딩만) | 실제 에이전트 요청 쌍 |
| v9 | `--self` client 쪽 PID == 자기 PID, `--port` 로 테스트 서버 LISTEN 줄의 PID (Windows) | — | 관리자 권한 프로세스 |
| v10 | 세 구역 출력, `--set/--restore` 레지스트리 왕복 (Windows, CI 에서만) | — | 실제 브라우저가 따르는지 |
