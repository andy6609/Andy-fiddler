# v8 노트 — 두 요청을 구조로 비교하고, 파일 하나로 남기기

> 코드: `lab/v8_diff_report/v8_diff_report.cpp`
> 실행: `./build/lab/v8_diff_report flows.jsonl 3 5 [--part reqHeaders] [--ignore "metadata.user_id"] [--report out.html [--redact]]`

---

## 1. 이 버전이 필요한 이유

"같은 작업을 다른 에이전트/클라이언트로 했을 때 요청이 어떻게 다른가" 가 이 프로젝트의 핵심 질문 중 하나다.
JSON 두 개를 눈으로 번갈아 보면 `messages[3].content[1]` 같은 깊은 차이를 놓친다 → **잎 경로 단위로 기계적으로 비교**.

---

## 2. ★ 꼭 이해하고 갈 것

### (A) 잎 경로 (leaf path)
```
$.model                          "m"
$.messages[1].content[0].type    "tool_use"
$.metadata.user_id               "u1"
```
- 객체는 키로, 배열은 **인덱스로** 비교. 그래서 배열 앞에 원소 하나가 끼면 뒤가 전부 "changed" 로 보인다 → 그럴 땐 side-by-side 줄 비교(본체 Compare 화면)가 더 읽기 쉽다. 두 방식을 같이 두는 이유.
- 키 순서도 관찰 대상 → `ordered_json` 으로 원본 순서 유지 (기본 `json` 은 알파벳순 정렬).

### (B) 정규화는 숨기지 않는다
- `user_id`, 요청 ID, 타임스탬프는 매번 달라서 진짜 차이를 묻는다 → `--ignore` 로 뺀다.
- 하지만 출력에 반드시 `5 ignored by: metadata.user_id messages[*].content` 처럼 **무엇을 몇 개 뺐는지** 남긴다. 모르는 사이에 빠진 차이가 결론을 바꾸면 안 되니까.

### (C) 결론 문장 없음
- 출력은 "4 added · 1 changed" 와 경로/값뿐. "도구 호출이 추가되었습니다" 같은 해석은 사람이 한다.

### (D) 보고서 두 방식
| | v8 (정적 HTML) | WireScope 본체 (데이터 + 뷰어 JS) |
|---|---|---|
| JS | 0줄, CSP `default-src 'none'` | 뷰어 JS 인라인 (외부 리소스 없음) |
| 받는 사람 쪽 위험 | 코드 실행 없음 | 우리 JS 만 실행 (캡처 값은 textContent) |
| 탐색 | 고정된 비교 하나 + 목록 | 검색, 필터, 아무 두 요청 비교, hex |
| 크기 | 작음 | 뷰어 JS(~70KB) + 데이터 |

사용자가 원한 건 "보고서 안에서도 탐색/비교" 라서 본체는 오른쪽. v8 은 "가장 안전한 최소 형태" 를 직접 만들어 보고 비교하려는 것.

### (E) escape 와 redact
- 캡처한 응답에 `<script>alert(1)</script>` 가 있어도 보고서에선 글자로 보인다 (테스트 + 스크린샷 확인).
- redact: body 제거, `authorization/cookie/set-cookie/x-api-key…` 값 가림, `?query` 가림, 비교표 **값**도 가림(경로·종류는 남김).
- **패턴 기반**이라 경로 자체의 ID, 다른 이름의 토큰 헤더, 노트는 남는다. 보고서 맨 위에 그 사실을 적는다.

---

## 3. 확인한 것 (`tests/lab_smoke.py v8`)

- 4 added · 1 changed · 4 unchanged, ignore 5개 표기, 키 순서, 헤더 diff, 비JSON body 는 바이트 사실만
- 보고서: script 없음 + escape, CSP, redact 시 `topsecret`/`sk-secret`/`session=abc`/`u2` 가 파일에 없음
