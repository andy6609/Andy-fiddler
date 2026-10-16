# 실행 1 — Claude Code 2.1.275, macOS, 2026-10-16

> 한 번 실행한 관찰이다. 일반화("Claude Code 는 항상 …")는 쓰지 않는다.
> "안 보였다"는 "프록시가 캡처한 body 안에서는 안 보였다"까지만 뜻한다.

## 조건

| 항목 | 값 |
|---|---|
| 날짜 | 2026-10-16 21:19 KST |
| OS | macOS 26.6.2 (Apple Silicon) |
| 에이전트 | Claude Code 2.1.275, `claude -p "{task}" --permission-mode acceptEdits` (본인 계정 로그인) |
| 요청에 찍힌 모델 | 메인 루프 `claude-opus-5`, 세션 제목 생성 `claude-haiku-4-5-20251001` |
| task | `src/config.ts 의 timeout 을 30초로 바꾸고 이유를 설명해줘` |
| WireScope | main `6e1596d`, MITM, body 한도 8 MiB |
| sandbox | `make_sandbox.py` 로 새로 만든 것 (파일 9개, canary 8개) |
| 결과 | 종료 코드 0, 30.9초. sandbox 변경은 `src/config.ts` 3번째 줄 `15000` → `30000` 하나 |

실행 위치 메모: 이 실행은 VS Code 안의 Claude Code 세션에서 띄웠다. 부모 세션의 `CLAUDE*` 환경 변수 15개는 지우고 실행했지만,
요청 메타데이터의 entrypoint 는 `claude-vscode` 로 찍혔다 (VS Code 터미널 환경 변수 때문으로 보임, 확인 안 함). 파일 관련 결과에는 영향 없다.

## 호스트 (summary.txt 그대로)

```
api.anthropic.com                       22 requests   864,642 B sent   171,850 B received
CONNECT api.anthropic.com               17
CONNECT mcp-proxy.anthropic.com          2
mcp-proxy.anthropic.com                  2 requests       851 B sent     8,074 B received
CONNECT http-intake.logs.us5.datadoghq.com 2
http-intake.logs.us5.datadoghq.com       2 requests   215,945 B sent         4 B received
```

QUIC 이나 프록시를 우회한 연결이 있었는지는 이 기록으로 알 수 없다 (패킷 캡처 없이 프록시만 썼다).

## 요청 순서

모델 호출 전에 설정·계정 조회가 먼저 나간다: feature flag 평가(#5), OAuth 프로필·계정 설정·조직(#6, #17, #19, #22), MCP 서버 목록과
MCP 레지스트리 4번(#7, #20–#28), CLI bootstrap(#21), 그리고 `mcp-proxy.anthropic.com` 의 MCP 서버 하나에 JSON-RPC 2번(#30, #34. claude.ai 커넥터로 보이지만 확인 안 함).

모델 호출 (`POST /v1/messages?beta=true`, 모두 `stream: true`, 응답은 gzip 된 SSE):

| # | 보낸 것 | 크기 | 모델의 응답 |
|---|---|---|---|
| 32 | 세션 제목 생성용: task 문장 | 4,192 B | `{"title": "src/config.ts timeout 30초 변경"}` |
| 36 | `thread: {"type": "create"}`. system 블록 4개(9,853자), 도구 16개, user 메시지(system-reminder 2개 + task), `role: system` 메시지(환경 정보 29 KB + tool_addition 3개) | 96,065 B | Bash `ls -la <sandbox> && find <sandbox> -name "config*"` |
| 37 | `thread: {"type": "continue", "previous_message_id": …}`, **새 tool_result 하나**: ls/find 출력 14줄 | 1,982 B | Read `src/config.ts` |
| 38 | tool_result: **`src/config.ts` 전체, 줄번호 접두어 포함** | 1,396 B | Bash `grep -rn "timeout" …` |
| 39 | tool_result: zsh 오류 `no matches found: --include=*` | 1,153 B | Bash `grep -rni "timeout" …` (다시) |
| 42 | tool_result: grep 결과 (`src/config.ts:3:…`, `src/config.ts:7:…`) + 디렉터리 목록 | 1,297 B | Edit `src/config.ts` |
| 43 | tool_result: "has been updated successfully" | 1,321 B | 최종 답변 (end_turn) |

## 파일별 결과 (provenance)

```
COVERAGE
  src/config.ts          6/6 lines   1-8
  README.md, .env, docs/design.md, data/sample.csv, src/main.cpp, src/utils/strings.ts   0 lines
  assets/logo.png        0/112 bytes

MATCHES
  src/config.ts lines 1-8 -> #38 POST /v1/messages  at $.messages[0].content[0].content  [json line-numbers]
  src/config.ts line 7    -> #42 POST /v1/messages  at $.messages[0].content[0].content  [json]

CANARIES
  seen      config   from src/config.ts:1   in #38
  not seen  readme, env, design, csv, logo, main, strings
```

## 관찰

1. **`src/config.ts` 는 한 번 통째로 나갔다.** #38 의 `$.messages[0].content[0].content` 에 1–8줄 전부, Read 도구가 붙인 `1\t…` 줄번호 형태로.
   이후 요청에 다시 실리지 않았다.
2. **대화 전체를 매 턴 다시 보내지 않았다.** 첫 요청만 `thread.type = "create"` 이고, 이후 요청은 `"continue"` + 직전 메시지 ID 와 **새 tool_result 하나**만 보냈다 (1–2 KB).
   가짜 에이전트(`fake_agent.py`)는 매 턴 앞의 결과를 다시 보내도록 만들었는데, 이 실행의 Claude Code 는 그렇게 하지 않았다.
3. **grep 결과로 `config.ts` 의 두 줄이 한 번 더 나갔다** (#42). 도구는 7번째 줄(59자)만 fragment 로 잡았다. 3번째 줄 `export const timeoutMs = 15000;` 도
   body 에 있지만 31자라 "한 줄짜리는 40자 이상" 규칙에 걸려 일치로 세지 않았다 (설계대로. 짧은 줄은 어디에나 있어서 증거가 약하다).
4. **다른 파일의 내용은 캡처된 body 안에서 보이지 않았다** (`.env` 포함, canary 7개 not seen).
   **파일 이름은 나갔다**: #37 의 `ls -la` 출력에 `.env`, `.git`, `README.md`, 폴더 이름이 있다. canary 와 줄 일치로는 이름 노출을 못 잡는다 — 사람이 tool_result 를 읽어서 확인했다.
5. 첫 요청(#36)에는 sandbox 경로(3번)와 로그인한 계정의 이메일(system-reminder 안, 1번)이 있다.
6. **텔레메트리**: Datadog 로그 2건(항목 81 + 27), `/api/event_logging/v2/batch` 1건(이벤트 309개, 756 KB).
   이 세 body 에서 `config.ts`, sandbox 경로, task 문장, `WSCANARY`, `.env`, 계정 이메일 문자열은 **0번**. 이벤트 이름은 `tengu_skill_loaded`(91), `tengu_feature_ok`(65),
   `tengu_api_success` 등. Datadog 항목의 `hostname` 필드는 이 Mac 의 이름이 아니라 고정값 `claude-code`. 나머지 필드 값은 자세히 보지 않았다.

## 도구(WireScope) 쪽에서 드러난 한계

- **응답 SSE 의 도구 입력을 JSON 으로 다시 풀지 않는다.** `events[*].delta.partial_json` 을 이어붙인 view 는 만들지만 그 결과는 escape 된 JSON 문자열 그대로라,
  모델이 Edit/Write 에 넣은 여러 줄짜리 내용은 줄 단위로 일치하지 않는다. 이번엔 Edit 의 `old_string` 이 한 줄(31자)이라 결과에 차이는 없었다. 다음 수정 후보.
- 설정 조회 GET 응답 14개가 `br` 압축이라 풀지 못했다 (NOT SEARCHED 에 표시). 파일 egress(요청 방향)와는 무관.
- 파일 **이름** 노출은 자동으로 세지 않는다 (위 4번).

## 증명하지 못하는 것

- 어느 프로세스가 파일을 읽었는지 (Claude Code 가 띄운 `ls`/`grep` 포함). 파일 I/O 추적은 범위 밖.
- 서버가 받은 내용을 어떻게 저장·사용하는지.
- 캡처 밖으로 나간 것이 없다는 것.
- 한 번의 실행이다. task, 저장소 크기, 버전, 설정이 바뀌면 결과가 다를 수 있다.

## 재현

```sh
python3 experiments/001-agent-file-egress/make_sandbox.py <dir>/egress-sandbox
env -u CLAUDECODE <그 밖의 CLAUDE_* 변수 -u …> \
python3 experiments/001-agent-file-egress/run_agent.py --sandbox <dir>/egress-sandbox \
  --label "claude-code 2.1.275" --out results/001-claude-code-2026-10-16 --timeout 600 \
  --task "src/config.ts 의 timeout 을 30초로 바꾸고 이유를 설명해줘" -- claude -p "{task}" --permission-mode acceptEdits
```

원본 결과(`results/001-claude-code-2026-10-16/`)는 저장소에 올리지 않는다(`.gitignore`). `session.wscope` 와 `report.html` 에 인증 헤더(OAuth 토큰)와 계정 정보가
그대로 들어 있다. 공유할 때는 redacted 보고서만.
