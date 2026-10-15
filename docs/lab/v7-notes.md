# v7 노트 — 엔진과 화면을 나누기

> 코드: `lab/v7_inspector_api/v7_inspector_api.cpp`
> 실행: `./build/lab/v1_flow_recorder flows.jsonl` 를 띄워 둔 채로 `./build/lab/v7_inspector_api flows.jsonl` → 브라우저 `http://127.0.0.1:18087/`

---

## 1. 왜 브라우저 UI 인가 (WireScope 의 구조 선택)

| 선택지 | 장점 | 단점 |
|---|---|---|
| 콘솔 출력 (v1~v6) | 단순 | 수천 건 탐색/비교 불가 |
| 네이티브 창 (Qt/Win32) | 앱 하나 | 화면 코드를 보고서로 재사용 불가, 빌드 무거움 |
| **로컬 HTTP API + 브라우저** | 같은 HTML/JS 를 **독립 HTML 보고서**로도 씀(v8), 화면/엔진 분리 | 로컬 서버 보안을 직접 챙겨야 함 |

---

## 2. ★ 꼭 이해하고 갈 것

### (A) revision polling
- 엔진: 데이터가 바뀔 때마다 `revision++`.
- 화면: `GET /api/state?revision=<마지막으로 받은 값>` 을 1초마다.
- 같으면 `{"unchanged":true}` 몇십 바이트. 다르면 요약 목록.
- WebSocket push 보다 단순하고, 탭을 새로 열어도 상태가 자연스럽게 맞는다. 본체도 이 방식.

### (B) 목록 = 요약, 상세 = 클릭할 때
- 1 MiB body × 3000건을 매초 보내면 안 된다. body(base64), h2 프레임 목록은 상세 API 에서만.

### (C) "localhost 니까 안전" 이 틀린 이유 — 4겹 방어
| 공격 | 시나리오 | 막는 것 |
|---|---|---|
| 단순 요청 | 아무 웹페이지 JS 가 `fetch('http://127.0.0.1:18087/api/state')` | **토큰** (CORS 때문에 bootstrap 응답을 못 읽어서 토큰을 모름) |
| DNS rebinding | evil.com 이 DNS 를 127.0.0.1 로 바꿔 '같은 출처'가 됨 → 응답도 읽힘 | **Host 검사** (`Host: evil.com:18087` 거절) |
| CSRF | 남의 페이지가 form/fetch 로 상태를 바꾸는 요청 | **Origin 검사** |
| 캡처 내용 실행 | 캡처한 HTML/JS 를 화면에 넣다가 실행됨 | **textContent** + **CSP** (`default-src 'self'`) |

테스트(`tests/lab_smoke.py v7`)가 앞의 세 가지 403 과 CSP 헤더를 확인한다. 본체 `src/main.cpp` 의 `set_pre_routing_handler` 가 같은 구조.

### (D) 파일 따라가기 (tail -f)
- 쓰는 쪽(v1)과 읽는 쪽(v7)이 다른 프로세스. 공유 매체 = JSONL 파일.
- 줄바꿈까지 와야 '완성된 레코드'. 반쪽 줄은 다음 확인 때까지 기다림 (테스트 있음).
- 본체는 한 프로세스 안에서 Store 를 직접 공유하므로 파일이 필요 없다. v7 은 "프록시 실험과 화면을 따로 띄우는" 학습용 구성.

---

## 3. 확인한 것

- 토큰 없음 / 남의 Host / 남의 Origin → 403, 페이지 CSP
- v1 이 쓴 JSONL 5줄 → 화면 5행, 클릭 시 body 디코딩 (headless Chrome 스크린샷으로 확인)
