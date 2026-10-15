# v3 노트 — HTTP/2 를 프레임 단위로

> 코드: `lab/v3_h2_observer/v3_h2_observer.cpp`
> 실행: `./build/lab/v3_h2_observer flows.jsonl` → `curl --http2 -x http://127.0.0.1:18083 --cacert flows.jsonl.ca.pem https://...`

---

## 1. v2 대비 변화

| | v2 (MITM) | v3 |
|---|---|---|
| ALPN | http/1.1 만 | 클라이언트가 고른 것(h2 우선)을 서버에도 똑같이 요청 |
| 프록시가 하는 일 | HTTP/1 파싱 후 **다시 써서** 보냄 | 복호화된 바이트를 **그대로** 재암호화해서 보냄 |
| 기록 단위 | 요청/응답 = Flow | 연결(h2-connection: 프레임 목록) + stream(h2-stream: 요청/응답) |

---

## 2. ★ 꼭 이해하고 갈 것

### (A) 프레임 = 9바이트 헤더 + payload
```
[length 24bit][type 8][flags 8][R 1 + stream id 31][payload ...]
```
- TLS 레코드 경계와 프레임 경계는 상관없다 → 방향마다 버퍼에 쌓고 완성된 프레임만 꺼냄(`nextFrame`).
- stream 0 = 연결 제어(SETTINGS/PING/GOAWAY/연결 WINDOW_UPDATE), 클라이언트 stream 은 홀수.
- 한 연결 안에서 stream 1, 3, 5 의 DATA 가 섞여서 온다 = multiplexing. 테스트에서 3개 병렬 요청이 한 연결, stream 1/3/5 로 기록됨.

### (B) HPACK 은 상태가 있다 (stateful)
- 정적 테이블 61개 + **연결마다 쌓이는 동적 테이블** + 허프만.
- 두 번째 요청부터 `user-agent` 같은 헤더는 "동적 테이블 62번" 같은 번호로만 온다.
- 그래서 **방향별로, 순서대로, 빠짐없이** 풀어야 한다. 중간 HEADERS 하나 놓치면 이후 전부 깨진다.
- 테스트의 "dynamic-table headers decoded on later streams too" 가 이걸 확인한다.

### (C) HEADERS 가 오는 세 가지 경우 (같은 stream 안에서)
| 방향 | 첫 HEADERS | 두 번째 HEADERS |
|---|---|---|
| C→S | 요청 헤더 | 요청 trailer |
| S→C | 응답 헤더 (`:status` 1xx 면 중간 응답, 다음 것이 진짜) | 응답 trailer |

### (D) observer(v3) vs bridge(WireScope 본체 `src/http2.cpp`)
| | observer | bridge |
|---|---|---|
| 바이트 | 그대로 통과 | 프레임을 다시 만들어 보냄 |
| SETTINGS / 흐름제어 | 클라와 서버가 직접 협상 | 양쪽 따로 협상 (프록시가 중간 버퍼) |
| 장점 | 단순, 원본 그대로 | 내용 수정 가능, 한쪽이 느려도 다른 쪽 독립, h2↔h1 변환 같은 확장 가능 |
| 단점 | 아무것도 못 바꿈, ALPN 이 양쪽 같아야 함 | 복잡 (stream ID 매핑, 큐, flow control) |

본체가 bridge 를 고른 건, 기록 외에도 나중에 요청 중단/재전송 같은 제어를 넣을 여지를 두려고. 단, 지금 본체도 내용을 바꾸지는 않는다.

---

## 3. 🟡 단순화한 것

- `SSL_read` 블로킹: 한쪽 TLS 레코드가 반쯤 왔으면 그동안 반대 방향이 잠깐 멈춘다. 본체는 non-blocking + `nghttp2_session_want_write`.
- CONNECT 직후 pre-read 바이트, h2c(평문 h2), PUSH_PROMISE 는 미지원.
- 프레임 기록은 연결당 2000개까지.

---

## 4. 확인한 것 (macOS, nghttpd 대상)

- 병렬 3요청 → 연결 1개, stream 1/3/5, stream별 DATA 바이트 = 파일 크기
- HPACK 해제 후 `:path`/`:status 200`, 응답 body = 파일, `x-h2-trailer: yes` 를 trailer 로 분류
- h2 POST body 기록
