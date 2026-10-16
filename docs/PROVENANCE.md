# Provenance — 로컬 파일의 어느 부분이 어느 요청에 실려 나갔나

- 작성: 2026-10-16
- 코드: `web/provenance.js` (판정), `web/app.js` TRACE 화면, `src/core.*` 로컬 파일 스냅샷, `scripts/provenance_cli.mjs`, `experiments/001-agent-file-egress/`
- 학습용 축소판: `lab/v11_provenance` ([노트](lab/v11-notes.md))

---

## 1. 무엇을 하나

WireScope 는 원래 요청에서 출발해 연결·패킷·바이트로 내려갔다. 이 기능은 출발점을 하나 더 둔다. **내 컴퓨터의 파일**에서 출발해, 그 내용이 캡처된 어느 요청(또는 응답) body 의 어느 위치에 있었는지 찾는다. 찾은 요청에서는 기존처럼 연결과 패킷으로 계속 내려갈 수 있다.

```
 로컬 파일 src/config.ts 1–8줄
        │  (JSON 문자열 escape 해제 → 줄번호 접두어 제거 → 줄 run 일치)
        ▼
 요청 #3  $.messages[2].content[0].content
        ▼
 연결 127.0.0.1:53211 | 127.0.0.1:18080  →  패킷  →  바이트
```

화면은 사이드바 TRACE 아래 두 개다.

| 화면 | 하는 일 |
|---|---|
| Find in bodies | 모든 body 를 해석된 상태(gzip·JSON·SSE·base64·multipart 해제 후)로 문자열 검색. 결과마다 JSON 경로와 변환을 표시 |
| Local files → requests | 등록한 로컬 파일마다 커버리지(본 줄 수), 일치 목록(파일 구간 → 요청·위치·변환), canary 표(본 것 / 못 본 것 / 출처 모름) |

---

## 2. 흐름

```
세션 archive (요청·응답 body base64, 로컬 파일 스냅샷)
   │
   ├─ body 하나 → view 여러 개    view = {요청, 방향, 위치(locator), 변환(transforms), 텍스트 또는 바이트}
   │
   ├─ canary 찾기                 WSCANARY-… 토큰: 파일:줄 ↔ 본 위치
   ├─ 줄 run 찾기                 파일의 연속된 줄 = view 의 연속된 줄
   ├─ fragment 찾기               40자+ 고유 줄이 다른 문장 안에 인용됨
   ├─ 바이트 찾기                 바이너리 파일: 통째로 / 최장 앞부분
   │
   └─ 중복 정리 → 커버리지 → 화면 / CLI / 보고서
```

같은 `provenance.js` 가 실시간 화면, 오프라인 HTML 보고서(인라인), node(CLI·테스트)에서 돈다. 판정 코드가 한 벌이라 화면과 CLI 결과가 갈라지지 않는다.

---

## 3. view — body 를 사람이 쓴 모양으로 되돌리기

파일 내용은 거의 그대로 나가지 않는다. JSON 문자열 안에서 `\n`·`\"` 로 escape 되거나, gzip 으로 압축되거나, 스트림 조각으로 쪼개지거나, base64 첨부가 된다. 그래서 body 하나를 여러 "view" 로 풀고, **어떻게 풀었는지(transforms)를 view 에 같이 적는다.** 일치를 보여줄 때 그 목록을 그대로 보여준다.

| transform | 뜻 | locator 예 |
|---|---|---|
| (없음) | 캡처된 바이트 그대로 | `body` |
| `gzip` / `deflate` | Content-Encoding 해제 (잘린 스트림은 해제된 앞부분 + note) | `body` |
| `json` | JSON 문자열 값 하나, escape 해제 | `$.messages[2].content[0].content` |
| `sse` | server-sent event 하나 | `events[3].delta.text` |
| `join` | 같은 필드를 이벤트 순서대로 이어붙임 (스트리밍된 글) | `events[*].delta.text (joined 12)` |
| `base64` | JSON 안 base64 / `data:` URL 해제 | `$.attachments[0].data` |
| `multipart` | multipart/form-data 파트 하나 | `part[1] name="file" filename="a.png"` |
| `form` | urlencoded 필드 하나 | `form.note` |
| `line-numbers` | 파일 읽기 도구의 줄번호 접두어 제거 (일치 단계에서 붙음) | — |

바이너리 view 는 바이트를 latin1 문자열로 들고 있어서 바이트 그대로 `indexOf` 할 수 있다.

---

## 4. 일치 종류와 규칙

| 종류 | 언제 | 규칙 |
|---|---|---|
| canary | 파일에 심은 `WSCANARY-…` 토큰이 view 에 있음 | 토큰 → 그 토큰이 있는 파일:줄. 어느 파일에도 없는 토큰은 "출처 모름"으로 따로 |
| lines | 파일의 연속된 줄이 view 의 연속된 줄로 나옴 | 줄은 앞뒤 공백 무시. 사소한 줄(짧거나 괄호뿐)은 run 을 이어 줄 뿐 시작 못 함. 의미 있는 줄 2개 이상, 또는 40자+ 의미 있는 줄 1개. run 끝의 빈 줄은 포함 안 함 |
| fragment | 40자+ 고유한 파일 줄이 다른 줄 안에 인용됨 | 같은 body 의 lines 일치가 이미 그 줄을 덮으면 생략 |
| bytes | 바이너리 파일 | 파일 바이트 전체가 그대로 / 아니면 4 KiB 단위 최장 앞부분(잘린 업로드) |

**중복 정리.** 같은 파일 구간이 한 body 의 여러 view 에서 보이면(원문 body, 이어붙인 스트림, 이벤트 자체) 하나만 남긴다. 우선순위는 구체적인 경로 > join > 원문 body.

**커버리지.** 파일의 의미 있는 줄 중 어떤 일치(lines/fragment)에든 포함된 줄의 비율. 바이너리 파일은 찾은 최장 바이트 / 파일 크기.

---

## 5. 증명하는 것과 못 하는 것

| 증명 | 못 함 |
|---|---|
| 이 바이트들이 **프록시가 캡처한** 이 요청/응답 body 안에 있었다 | 어느 **프로세스**가 그 파일을 읽었는지 |
| canary 는 그 파일에서 온 바이트다 (무작위 토큰이라 다른 출처가 없음) | 서버가 그 내용을 어떻게 저장·사용했는지 |
| 어떤 canary 는 캡처된 어떤 body 에도 없었다 | 캡처 밖으로 나간 게 없다는 것 (QUIC, 인증서 고정, 프록시 무시, body 한도 밖) |
| | 같은 줄이 다른 곳에서 왔을 가능성 (canary 가 없는 일반 줄) |

화면과 CLI 는 이 경계를 결과 옆에 문장으로 적는다. "검색 못 한 범위"(body 한도, 잘린 body, 풀지 못한 인코딩, redacted)도 같이 보여준다.

---

## 6. 로컬 파일 스냅샷과 개인정보

- 엔진은 **경로를 스스로 열지 않는다.** 브라우저(파일/폴더 선택)나 스크립트(`/api/files`)가 준 바이트만 저장한다. 엔진이 파일 시스템을 돌아다니게 만들면 로컬 API 가 파일 읽기 통로가 되기 때문이다.
- 한도: 파일당 2 MiB, 합계 32 MiB, 256개. 폴더 추가는 `.git`·`node_modules` 를 건너뛴다.
- 스냅샷은 세션의 일부다. `.wscope` 와 보통 보고서에 들어간다. **redacted 보고서에는 통째로 빠진다.**
- 실험용 저장소에만 쓰는 것을 전제로 한다. 진짜 비밀값이 든 파일은 등록하지 않는다.

---

## 7. body 한도

기본은 방향별 1 MiB 보관이다. 실험에서는 `--body-limit MiB`(최대 32)로 올린다 (`run_agent.py` 는 8 MiB). archive 에 실제 적용된 한도가 `bodyLimit` 으로 남고, 화면은 "이 한도 밖은 검색하지 않았다"고 적는다.

---

## 8. 검증

| 테스트 | 내용 |
|---|---|
| `tests/provenance_test.mjs` (node) | view 종류별(gzip·잘린 gzip·br·JSON·SSE·join·base64·data URL·multipart·form), 검색, canary, 줄 run(부분 읽기·재들여쓰기·사소한 줄·긴 줄·잘린 끝), 바이너리, fragment, 중복 정리, analyze 종단 |
| `tests/core_tests.cpp` | 스냅샷 저장·한도·archive 왕복·예전 archive 호환·redact 제외, body 한도 변경 |
| `tests/integration_test.py` | `/api/files`, redacted 보고서에 스냅샷 없음, 보고서에 provenance.js 인라인 |
| `tests/experiment_dryrun_test.py` | 정답을 아는 가짜 에이전트로 실험 키트 전체: 보낸 줄만 정확히, 안 보낸 canary 는 안 보임, 이전 턴 재전송도 보임 |
| headless Chrome | Find in bodies, Local files → requests, inspector, 파일 추가/삭제, 오프라인·redacted 보고서 |

**실제 에이전트(Claude Code, Codex 등)로는 아직 돌리지 않았다.**

---

## 9. 일부러 여기까지만 한 것, 다음 후보

- **파일 I/O 추적 없음.** "어느 프로세스가 읽었나"는 macOS `fs_usage`, Windows ETW/Process Monitor 로 따로 기록해 시간·PID 로 맞춰야 한다. 엔진이 커널 수준 추적을 하려면 권한·드라이버 문제가 커서 별도 단계로 뒀다.
- **의미 단위 비교 없음.** 요약·번역·재작성된 내용은 못 찾는다. 줄과 바이트가 그대로 남은 경우만 다룬다. "비슷하다"를 판정하는 순간 판단 문장이 생기기 때문에 일부러 피했다.
- **배열 순서 기반 run.** 파일 줄이 다른 순서로 재배열돼서 나가면 짧은 run 여러 개로 보인다.
- **br / zstd 미해제.** 브라우저 API 가 지원하지 않는다. note 로 표시한다.
- **WebSocket·HTTP/3 body 는 대상 아님.** 프록시가 메시지 단위로 기록하지 않거나 볼 수 없는 경로다.
EOF
git add docs/PROVENANCE.md && git commit -q -m "docs: PROVENANCE.md — 로컬 파일 → 요청 추적의 흐름, view 와 변환 표, 일치 종류·규칙·중복 정리·커버리지, 증명하는 것/못 하는 것, 스냅샷과 개인정보, 검증, 일부러 안 한 것" && git log --oneline -1