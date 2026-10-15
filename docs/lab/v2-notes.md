# v2 노트 — 통과시킬 것인가, 끊고 볼 것인가

> 코드: `lab/v2_tls_recorder/v2_tls_recorder.cpp`
> 실행: `./build/lab/v2_tls_recorder flows.jsonl` (passthrough) / `... flows.jsonl --mitm` (TLS 종단)

---

## 1. 두 모드 비교 — "무엇이 보이나"

| 보이는 것 | passthrough (단계 1) | MITM (단계 2) |
|---|---|---|
| 목적지 host:port | ✅ CONNECT 줄 | ✅ |
| SNI (ClientHello) | ✅ **암호화 전이라 평문** | ✅ |
| TLS 레코드 종류/크기 | ✅ 5바이트 헤더 | (프록시가 직접 처리) |
| 방향별 바이트 수, 타이밍 | ✅ | ✅ |
| 메서드, 경로, 헤더, body | ❌ 암호문 | ✅ 평문 |
| 클라이언트 설정 필요 | 프록시 지정만 | 프록시 지정 + **CA 신뢰** |
| 깨지는 경우 | 거의 없음 | 인증서 pinning, 자체 trust store 쓰는 앱 |

→ WireScope 본체 툴바의 **Decrypt HTTPS** 체크박스가 이 두 모드 전환이다.

---

## 2. ★ 꼭 이해하고 갈 것

### (A) Stream 추상화
- v1 의 Reader 는 `recv` 를 직접 불렀다. TLS 안쪽은 `SSL_read` 를 불러야 한다.
- Reader 가 `Stream*` 만 보게 바꾸면 **HTTP 파서는 그대로** 두 경로에서 돈다.
- local-proxy-lab `proxy_v4` 의 `SockStream/TlsStream` 과 같은 결론. 본체에서는 `Channel` 구조체가 `socket + SSL*` 를 같이 들고 같은 역할을 한다.

### (B) 인증서 두 장의 역할
```
WireScope lab v2 CA (self-signed, CA:TRUE)   ← 클라이언트가 믿어야 하는 것 (--cacert)
   └─ localhost (CA:FALSE, SAN=DNS:localhost, EKU=serverAuth)   ← 접속할 때마다 즉석 발급
```
- 클라이언트가 확인하는 것: 체인 → 믿는 CA / SAN 에 host 가 있나 / 기간.
- SAN 이 없고 CN 만 있으면 요즘 클라이언트는 거부한다.

### (C) upstream 검증을 끄면 안 되는 이유
- 프록시 ↔ 진짜 서버 구간에서 인증서를 안 보면, 그 구간에 또 다른 MITM 이 있어도 모른다.
- 그래서 `SSL_VERIFY_PEER` + `SSL_set1_host`. 테스트에서는 `SSL_CERT_FILE` 로 테스트 서버 CA 를 믿게 했다.

### (D) ALPN
- TLS 핸드셰이크 안에서 "이 연결로 h2 할래 / http/1.1 할래" 를 정한다.
- v2 는 http/1.1 만 고르므로 `curl --http2` 도 1.1 로 내려온다 (테스트로 확인).
- 브라우저/AI 클라이언트는 대부분 h2 → 실제 모습을 보려면 v3.

---

## 3. 🟡 단순화한 것

| 부분 | v2 | 본체 |
|---|---|---|
| CA | 실행마다 새로 생성, 메모리에만 키 | 파일 저장·재사용, 개인키 ACL/권한 제한, Windows ROOT 설치/삭제 |
| pre-read ClientHello (MITM) | 에러로 기록 | 에러로 처리 (proxy_v4 는 BIO 선주입) |
| leaf 캐시 | 무제한 | 2048개 상한 |
| TLS 안쪽 Host 검사 | 없음 | Host 가 CONNECT authority 와 다르면 거절 |

---

## 4. 확인한 것 (macOS, `tests/lab_smoke.py v2`)

- passthrough: SNI=localhost, 첫 레코드 Handshake(22), 응답 바이트에 평문 `hello world` 없음
- MITM: GET/POST/chunked 복호화 기록, h2 요청 → http/1.1, CA 미신뢰 클라이언트는 실패하고 그 실패도 기록
