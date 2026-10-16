# v9 노트 — 이 연결은 누가 열었나 (Windows)

> 코드: `lab/v9_win_owner/v9_win_owner.cpp` (Windows 전용, 다른 OS 에선 안내 한 줄)
> 실행: `build-windows\lab\v9_win_owner.exe` / `... --port 443` / `... --self`

---

## 1. v1~v8 대비 변화

| | v1~v8 | v9 |
|---|---|---|
| 질문 | 무엇이 오갔나 (요청, 패킷, 바이트) | **누가** 보냈나 (프로세스) |
| 보는 것 | 연결 위의 내용 | OS 가 관리하는 TCP 연결 표 |
| 내용 해석 | 함 | 전혀 안 함 |
| 플랫폼 | macOS/Windows 공통 | Windows 전용 (`GetExtendedTcpTable`) |

---

## 2. ★ 꼭 이해하고 갈 것

### (A) 소켓에는 "주인 PID" 가 적혀 있지 않다
프록시가 `accept()` 로 받은 소켓에서 알 수 있는 건 상대 주소(`127.0.0.1:52344`)뿐이다.
누가 그 포트를 쓰는지는 **OS 의 연결 표**에 있다. `netstat -ano` 가 보여 주는 바로 그 표다.

```
GetExtendedTcpTable(..., AF_INET, TCP_TABLE_OWNER_PID_ALL)
  → MIB_TCPROW_OWNER_PID[]  { dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort, dwOwningPid }
```

### (B) loopback 연결은 표에 두 줄
```
[client row] ESTABLISHED  127.0.0.1:52344 -> 127.0.0.1:18080  pid 716   curl.exe
[proxy row]  ESTABLISHED  127.0.0.1:18080 -> 127.0.0.1:52344  pid 2600  WireScope.exe
```
같은 TCP 연결의 양 끝이 같은 PC 에 있으니 두 줄이다. 프록시는 accept 한 소켓의 상대 주소를 알고 있으므로
**local = 그 주소, remote = 프록시 주소** 인 줄을 고르면 된다. `--self` 가 이 과정을 자기 자신으로 재현한다
(앱 역할과 프록시 역할이 같은 프로세스라서 두 줄의 PID 가 같게 나온다).

### (C) 포트 값의 함정
`dwLocalPort` 는 DWORD 인데 **아래 16비트만** 쓰고, 그것도 **네트워크 바이트 순서**다.
`ntohs(u_short(dwLocalPort & 0xFFFF))` 를 빼먹으면 443 이 47873(0x01BB → 0xBB01)으로 보인다.

### (D) 표는 '조회한 순간의 사진'
- curl 한 번 같은 짧은 연결은 끝나면 표에서 사라진다 → 본체는 **accept 직후, 첫 바이트를 읽기 전에** 조회한다.
- PID 는 재사용된다. 부모 PID 는 부모가 먼저 끝났다면 이미 다른 프로그램일 수 있다 (화면에도 이 문장을 그대로 둔다).
- 두 번 부르는 사이에도 연결이 생긴다 → `ERROR_INSUFFICIENT_BUFFER` 면 여유를 두고 다시.

### (E) PID → 프로그램: 권한이 다른 두 길
| API | 얻는 것 | 권한 |
|---|---|---|
| `CreateToolhelp32Snapshot` | exe 이름, 부모 PID | 필요 없음 |
| `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageNameW` | exe 전체 경로 | 관리자 권한 프로세스는 실패할 수 있음 |
| `NtQueryInformationProcess(ProcessCommandLineInformation)` (본체만) | 명령줄 | 위와 같음, Windows 8.1+ |

명령줄이 중요한 이유: Claude Code 와 Gemini CLI 는 둘 다 `node.exe` 다. exe 이름만으로는 구분이 안 되고,
명령줄(`node.exe ...\claude-code\cli.js`)을 봐야 갈린다. 대신 명령줄에는 토큰이 들어 있을 수 있어서
본체의 redact 보고서는 경로와 명령줄을 `[redacted]` 로 바꾼다.

---

## 3. 🟡 단순화한 것
- IPv4 표만 본다 (IPv6 는 `AF_INET6` + `MIB_TCP6ROW_OWNER_PID` 로 같은 방식).
- UDP(`GetExtendedUdpTable`)는 안 본다. UDP 표에는 remote 주소가 없어서 local 포트로만 맞출 수 있다.
- 캡처한 패킷을 프로세스에 붙이는 건 안 한다 (패킷마다 표를 다시 읽어야 하고, 짧은 연결은 놓친다).

---

## 4. 확인한 것 / 못 한 것

확인 방법은 GitHub Actions `windows-latest` 러너(Windows Server 2025)의 `tests/lab_smoke.py` 결과다.
결과는 [docs/WINDOWS.md](../WINDOWS.md) 의 "Windows 에서 확인한 것" 절에 실행 번호와 함께 적는다.

- `--self`: client 쪽 줄의 owning PID == 데모 자신의 PID
- `--port <테스트 HTTP 서버 포트>`: `LISTEN` 줄의 PID == 테스트 프로세스 PID
- ❌ 관리자 권한 프로세스에 대한 `OpenProcess` 실패 경로는 러너에서 따로 만들지 않았다 (러너는 관리자로 돈다).
