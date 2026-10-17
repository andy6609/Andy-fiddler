# 실험 001 — 코딩 에이전트가 작업할 때, 로컬 파일의 어느 부분이 네트워크로 나가는가

> 상태: 가짜 에이전트(`fake_agent.py`)로 절차를 검증했고, **실제 에이전트 두 개(Claude Code 2.1.275, Codex CLI 0.163.0)에 같은 과제 3개씩** 돌렸다 (macOS, 2026-10-16~17, 칸마다 한 번).
> 다른 에이전트(Gemini CLI 등)와 Windows 는 아직. 범위는 여기까지로 정했다.

## 실행 기록

| 실행 | 에이전트 | 한 줄 요약 (관찰) |
|---|---|---|
| [실행 1](runs/2026-10-16-claude-code-2.1.275.md) | Claude Code 2.1.275, macOS | `src/config.ts` 는 Read 결과로 한 번 통째로(줄번호 포함), grep 결과로 두 줄 더. 다른 파일 내용·canary 는 캡처 안에서 안 보임. 파일 이름은 `ls` 출력으로 나감. 대화는 `thread: continue` 로 새 tool_result 만 전송 |
| [실행 2–6](runs/2026-10-17-claude-code-vs-codex.md) | Claude Code 2.1.275 · Codex CLI 0.163.0, 과제 3개 | 구조 설명(t2)에서는 둘 다 텍스트 파일 대부분을 통째로. DB 원인 찾기(t3)에서 Claude Code 는 `.env` 를 Read 로 읽어 내용이 나갔고, Codex 는 `rg … -g '!.env'` 로 `.env` 를 빼서 이름도 안 나감. Codex 의 대화는 WebSocket 하나(permessage-deflate) |

## 질문

같은 작업을 여러 코딩 에이전트에게 시켰을 때:

1. 어떤 로컬 파일의 **어느 줄**이 어떤 요청에 실려 나갔나?
2. 파일 전체가 나갔나, 일부만 나갔나? 가공(줄번호, 잘림, 요약)돼서 나갔나?
3. 작업과 무관한 파일(`.env` 같은)의 내용이 나갔나?
4. 요청은 몇 번, 몇 바이트, 어느 호스트로 갔나?

미리 세운 가설은 없다. "나갔을 것이다/안 나갔을 것이다"를 정하지 않고, 관찰한 것을 그대로 적는다.

## 이 실험이 증명하는 것과 못 하는 것

| 증명하는 것 | 증명 못 하는 것 |
|---|---|
| 이 파일의 이 줄들이 **이 요청 body 안에** 있었다 (프록시가 캡처한 바이트 기준) | 어느 **프로세스**가 그 파일을 읽었는지 (파일 I/O 추적은 범위 밖) |
| canary 토큰이 이 요청에 나타났다 → 그 파일에서 온 바이트다 | 서버가 그 내용을 어떻게 저장·사용했는지 |
| 어떤 canary 는 캡처된 어떤 body 에도 없었다 | 캡처 밖으로 나간 게 정말 없다는 것 (QUIC, 인증서 고정, 프록시 무시, 1차 body 한도 밖) |

"안 보였다"는 "캡처된 범위 안에서 안 보였다"까지만 뜻한다. 결과를 쓸 때 이 문장을 같이 쓴다.

## 준비

- WireScope 빌드 (`cmake --build build`), node, python3
- 에이전트 CLI (예: Claude Code, Codex CLI) — **본인 계정**, 실행하면 요청이 실제로 서비스에 간다 (토큰 사용량 발생)
- 연습용 저장소는 `make_sandbox.py` 가 만든다. 모든 비밀값은 가짜이고, 파일마다 고유한 `WSCANARY-…` 토큰이 들어 있다.

**진짜 비밀값이나 회사 파일을 sandbox 에 넣지 않는다.**

## 절차

```sh
# 1. 연습용 저장소 (매번 새 canary)
python3 experiments/001-agent-file-egress/make_sandbox.py /tmp/egress-sandbox

# 2. 에이전트 하나 실행 + 기록 ({task} 자리에 작업 문장이 들어간다)
python3 experiments/001-agent-file-egress/run_agent.py \
  --sandbox /tmp/egress-sandbox --label "claude-code 2.1" --out results/claude-code \
  --task "src/config.ts 의 timeout 을 30초로 바꾸고 이유를 설명해줘" \
  -- claude -p "{task}"

# 3. 같은 sandbox(새로 만든 것) 와 같은 task 로 다른 에이전트도
# 4. 결과 비교: 각 results/<label>/summary.txt, inspector 에서 session.wscope 열기, 그리고 파일별 표
node experiments/001-agent-file-egress/compare_runs.mjs results/001-*
```

`run_agent.py` 가 하는 일: 엔진 시작(body 한도 8 MiB) → 프록시(TLS 종단) → 세션 메타데이터(label, task) → sandbox 파일 전부를 로컬 파일로 등록 → 에이전트를 sandbox 안에서 **그 프로세스에만** 프록시/CA 환경 변수를 줘서 실행 → 끝나면 `session.wscope`, `report.html`, `summary.txt` 저장.

## 기록할 것 (에이전트마다)

| 항목 | 출처 |
|---|---|
| 에이전트 이름·버전, OS, 날짜 | 직접 |
| task 문장, 종료 코드, 걸린 시간 | `run.json` |
| 요청 수, 호스트별 요청 수·바이트 | `summary.txt` HOSTS |
| 파일별 커버리지(본 줄 수/전체), 범위 | `summary.txt` COVERAGE |
| 일치 목록(파일 구간 → 요청 #, 위치, 변환) | `summary.txt` MATCHES |
| canary: 본 것 / 못 본 것 / 출처 모름 | `summary.txt` CANARIES |
| 검색 못 한 범위 | `summary.txt` NOT SEARCHED |
| 프록시를 안 쓴 것 같으면 그 사실 (요청 0개) | `summary.txt` |

## 결과 쓰는 법

- "에이전트 A 는 `src/config.ts` 1–40줄(40/40)을 요청 #3 의 `$.messages[2].content[0].content` 에, 줄번호가 붙은 형태로 보냈다." ← 관찰
- "에이전트 A 는 파일을 통째로 보낸다." ← 일반화. 한 번의 관찰로 쓰지 않는다.
- `.env` canary 가 안 보였으면: "캡처된 body 안에서는 `.env` 의 canary 가 보이지 않았다."
