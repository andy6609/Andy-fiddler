# v1 노트 — 중계에서 기록으로

> 코드: `lab/v1_flow_recorder/v1_flow_recorder.cpp`
> 실행: `./build/lab/v1_flow_recorder flows.jsonl` → `curl -x http://127.0.0.1:18081 http://...`

---

## 1. local-proxy-lab proxy_v2(M2) 대비 무엇이 달라졌나

| 항목 | proxy_v2 (M2) | v1_flow_recorder |
|---|---|---|
| 목적 | HTTP 파싱해서 **제대로 전달** | 전달 + **지나간 걸 Flow 로 남기기** |
| 결과물 | 콘솔 로그 | `flows.jsonl` (한 줄 = 요청+응답 하나) |
| body | 전달만 | 앞 1 MiB 보관 + **전체 크기는 끝까지 카운트** |
| 시간 | 없음 | timeline: `request.headers → request.end → response.headers → response.end` (ms) |
| 연결 정보 | 없음 | endpoint 쌍 2개 (클라↔프록시, 프록시↔서버) |
| 실패 | 로그 찍고 끝 | **실패도 Flow 로 기록** (`error` 필드) |
| 플랫폼 | WinSock 전용 | `lab_net.hpp` 로 Windows/macOS 둘 다 |

---

## 2. ★ 꼭 이해하고 갈 것

### (A) "보관"과 "세기"를 나눈 이유 — `Captured`
- 2 GB 동영상 업로드가 지나가도 메모리에 다 올리면 안 된다 → 앞 1 MiB만 보관.
- 그런데 **크기까지 1 MiB로 적으면 거짓말**이 된다. 그래서 `total`은 끝까지 센다.
- 결과: `captured=1048576, total=1572864, truncated=true` 처럼 사실 그대로.
- WireScope 본체도 같은 규칙. 거기서는 잘린 body에 sha256도 안 쓴다(앞부분 해시를 전체 해시라고 착각하지 않게).

### (B) body 가 어디서 끝나는지 — 3가지 framing
| 헤더 | 끝나는 지점 | 함수 |
|---|---|---|
| `Content-Length: N` | 정확히 N 바이트 | `forwardExact` |
| `Transfer-Encoding: chunked` | 크기 0 청크 + trailer + 빈 줄 | `forwardChunked` |
| 둘 다 없음 (응답) | 서버가 연결 끊을 때 | `forwardUntilClose` |

- 이걸 모르면 keep-alive(한 연결에 요청 여러 개)가 불가능하다. 다음 요청이 어디서 시작하는지 모르니까.
- chunked 는 **전달할 때 껍데기 포함, 기록할 때 내용만**. → 기록된 바이트 수 ≠ 소켓으로 오간 바이트 수.

### (C) endpoint 쌍
- `127.0.0.1:53211 | 127.0.0.1:18081` = 클라이언트 쪽 소켓, `127.0.0.1:53212 | 93.184.216.34:80` = 서버 쪽 소켓.
- 이건 **패킷 캡처에서 같은 연결을 찾는 열쇠**다 (v4/v5, 본체의 "Packets" 탭).
- 단, 한 연결에 요청이 여러 개(keep-alive) 지나가면 같은 key 를 공유한다 → "이 패킷이 이 요청" 일대일 증거는 아님.

---

## 3. 🟡 일부러 단순하게 둔 것 (본체에서 해결)

| 부분 | v1 | WireScope 본체 |
|---|---|---|
| CONNECT/HTTPS | 501 로 거절 | v2 → `proxy.cpp` |
| 요청 스머글링 방어 (CL+TE 동시) | 없음 | `framing()` 에서 거절 |
| 헤더/줄 길이 상한 | 줄 64 KB, 헤더 200개 | 헤드 전체 64 KB |
| 스레드 | 연결마다 detach | 연결 수 상한 64 + 종료 시 join |
| `std::stoull` 실패 | 예외로 스레드 종료 | `from_chars` 로 검증 |

---

## 4. 확인한 것 (macOS, `tests/lab_smoke.py v1`)

- GET / 5 KB 바이너리 POST(sha256 일치) / chunked + trailer / 1.5 MiB 응답 전체 전달
- JSONL 5줄, 1 MiB 보관 + total 1.5 MiB, 연결 실패도 error flow 로 기록
- Windows 에서는 아직 안 돌려봄 (WinSock 분기는 `lab_net.hpp` 에 있음)
