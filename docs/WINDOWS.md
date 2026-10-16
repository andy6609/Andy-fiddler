# WireScope — Windows 버전

작성: 2026-10-15. main(macOS 개발 호스트에서만 검증된 상태)에서 `windows` 브랜치로 갈라져 Windows 에서 빌드·실행·검증되도록 만들었고, 2026-10-16 main 에 합쳤다.

> **한 줄 상태**: GitHub Actions `windows-latest` 러너(Windows Server 2025, MSVC)에서 /W4 경고 0 으로 빌드되고,
> core · integration · windows · lab 테스트를 실제 Windows 위에서 돌린 결과가 아래 3절이다.
> **사람이 Windows 데스크톱(10/11)에서 직접 실행해 본 적은 아직 없다.** Npcap 라이브 캡처, 인증서 신뢰 설치
> (사용자 확인 대화상자), 실제 AI 클라이언트 관찰도 아직이다 (4절).

관련: [인수인계](AI-HANDOFF.md) · [관찰 범위](COVERAGE.md) · [lab v9](lab/v9-notes.md) · [lab v10](lab/v10-notes.md)

---

## 1. main 대비 달라진 것

| 영역 | 변경 | 왜 |
|---|---|---|
| 빌드 | `vcpkg.json`(openssl, nghttp2), `CMakePresets.json`(`windows-msvc`), `scripts/build-windows.ps1` | Visual Studio 만 있으면 한 줄로 빌드 |
| CI | `.github/workflows/windows.yml`, `.github/ci_annotate.py` | Mac 에서는 Windows 를 못 돌린다 → 러너가 증거 |
| 언어 표준 | C++20 → C++17 | 사용자 결정 (다른 세션 a3 를 거쳐 전달됨). `u8path`, `startsWith/endsWith` 헬퍼 |
| **새 기능: 프로세스 귀속** | `src/process.cpp`, 화면 Process 열·PROCESSES 필터 | 같은 127.0.0.1:18080 으로 들어오는 curl/node/python/브라우저를 구분 |
| **새 기능: 시스템 프록시** | `src/sysproxy.cpp`, "Use as system proxy" 버튼 | 브라우저 등 프록시 설정이 없는 앱 관찰. 명시적 버튼만, 백업 후 복원 |
| Windows 정확성 | 5절 표 (connect 실패 감지, 한글 경로, pcap_stat, ssize_t, 콘솔 닫기 …) | Windows 에서만 다르게 동작하는 곳 |
| lab | v9(연결 → 프로세스), v10(프록시 설정 세 군데) + Windows 수정(setvbuf, OpenSSL FILE*, 텍스트 모드 stdout) | 학습용 버전도 Windows 에서 돌게 |
| 테스트 | `tests/h2_server.py`(nghttpd 대신), `tests/windows_test.py` | Windows 에는 nghttpd 가 없고, Windows 전용 기능은 Windows 에서만 확인 가능 |

---

## 2. 빌드와 실행

### 필요한 것
- Visual Studio 2022 이상 + **"C++를 사용한 데스크톱 개발"** 워크로드 (MSVC, CMake, vcpkg 포함)
- (캡처할 때만) [Npcap](https://npcap.com/) — 설치할 때 **"Support loopback traffic"** 체크. 빌드에는 필요 없다.
- (테스트할 때만) Python 3 + `pip install h2`, OpenSSL 계열 curl (아래 주의)

### 빌드
```powershell
git switch windows
.\scripts\build-windows.ps1                 # 빌드 + core 단위 테스트
.\scripts\build-windows.ps1 -Test all       # + integration / lab / windows 테스트
.\scripts\build-windows.ps1 -Package        # dist\WireScope-windows-x64.zip (exe + web\ + OpenSSL/nghttp2 DLL)
```
처음 한 번은 vcpkg 가 OpenSSL 과 nghttp2 를 소스에서 빌드한다 (러너에서 약 9분).
CI 가 만든 zip 은 각 실행의 Artifacts(`WireScope-windows-x64`)에도 있다 (GitHub 로그인 필요).

### 실행
```powershell
.\build-windows\Release\WireScope.exe       # 브라우저가 http://127.0.0.1:17890 을 연다
```
- 데이터(로컬 CA, 시스템 프록시 백업): `%LOCALAPPDATA%\WireScope\`
- 프록시와 캡처는 화면에서 누르기 전까지 꺼져 있다. 시스템 설정도 버튼을 누르기 전엔 안 바꾼다.

### 클라이언트를 프록시로 보내는 세 가지 길
| 대상 | 방법 |
|---|---|
| 브라우저, 대부분의 Windows 앱, Python urllib | 툴바 **Use as system proxy** (WinINET 설정을 127.0.0.1:포트로, 끄면 원래대로) |
| curl, Node.js CLI (Claude Code, Codex CLI, Gemini CLI), git, pip | 그 PowerShell 창에서 `$env:HTTPS_PROXY="http://127.0.0.1:18080"` (+ HTTPS 평문이 필요하면 `$env:NODE_EXTRA_CA_CERTS="$env:LOCALAPPDATA\WireScope\root-ca.pem"`) — Certificate 대화상자에 복사용 문구가 있다 |
| 위 둘 다 안 따르는 앱 | 앱 자체의 프록시 설정. 그래도 안 되면 프록시로는 못 본다 → 패킷 캡처(Npcap)로 연결·바이트만 |

시스템 프록시를 켜도 **CLI 에이전트는 따르지 않는다**. 이건 버그가 아니라 Windows 에 프록시 설정이 세 군데 있기 때문이다 ([lab v10](lab/v10-notes.md)).

### 이 브랜치에서 화면에 새로 생긴 것
- **Process 열**: 요청마다 그 연결을 연 프로세스의 exe 이름과 PID. 상세(Overview)에는 exe 경로, 명령줄, 부모 프로세스와
  "accept 시점에 한 번 읽음, PID 는 재사용될 수 있음" 문장. 사이드바 **PROCESSES** 로 PID 별 필터.
- **Use as system proxy**: 프록시가 켜져 있을 때만 누를 수 있다. 끄기 / 프록시 중지 / 정상 종료 / 콘솔 창 닫기 때 원래 값으로 되돌린다.
  WireScope 가 비정상 종료돼 설정이 남아 있으면 다음 실행에서 툴바에 경고와 **Restore original** 이 뜬다.
- redact 보고서는 프로세스의 경로와 명령줄을 `[redacted]` 로 바꾼다 (사용자 이름, 프로젝트 경로, 인자로 넘긴 토큰).

---

## 3. Windows 에서 확인한 것

환경: GitHub Actions `windows-latest` = Windows Server 2025 Datacenter 10.0.26100, MSVC (VS 2022), vcpkg OpenSSL 3 + nghttp2,
Python 3.12 + h2, curl.se 공식 Windows curl(LibreSSL + nghttp2). 러너는 관리자 권한, Npcap 없음.

기준 실행: [run 38759644492](https://github.com/andy6609/Andy-fiddler/actions/runs/38759644492) (커밋 `c5255df`, 2026-10-16) — **4개 테스트 모두 통과**.
아래 값은 그 실행의 annotation(로그인 없이 실행 페이지에서 보임)에 남은 원자료를 옮긴 것이다.

| 테스트 | 결과 | 무엇을 확인했나 |
|---|---|---|
| MSVC 빌드 `/W4` | 오류 0, 경고 0 | 본체, lab v1~v5·v7~v10, 단위 테스트 (v6 은 Npcap SDK 가 없어 빌드에서 빠짐) |
| `core` (단위) | 104 checks, 0 failures | 인코딩, 패킷 해석, pcap/pcapng, 세션 저장/복원, 보고서, 프로세스 기록의 목록 축약·redact |
| `integration` | 48 ok, 0 FAIL | curl → WireScope → 로컬 HTTP / HTTPS(MITM) / HTTP/2(Python h2 서버, 5개 병렬 스트림, trailer) / passthrough / 거부된 upstream / 내보내기·가져오기 |
| `lab` | 88 ok, 0 FAIL | lab v1~v10 스모크 (v6 은 빌드에서 빠져 건너뜀) |
| `windows` | 35 ok, 0 FAIL | 아래 원자료 |
| `scripts/build-windows.ps1 -Package` | 성공 | zip: `WireScope.exe`, `libssl-3-x64.dll`, `libcrypto-3-x64.dll`, `nghttp2.dll`, `web\index.html`, `app.css`, `app.js` |

`windows` 테스트가 남긴 원자료 (그대로):
```text
process detail: {"commandLine": "D:/a/_temp/curl/curl-8.23.0_1-win64-mingw/bin/curl.exe -sS -x http://127.0.0.1:51594
                 http://127.0.0.1:51586/hello?who=curl-plain", "name": "curl.exe", "parentName": "python.exe", "parentPid": 9728,
                 "path": "D:\\a\\_temp\\curl\\curl-8.23.0_1-win64-mingw\\bin\\curl.exe", "pid": 6852, "source": "GetExtendedTcpTable at accept"}
CA path reported: C:\Users\RUNNER~1\AppData\Local\Temp\wirescope-win-i58by_ub\한글 데이터 폴더\root-ca.pem
original WinINET: {"autoConfigUrl": "", "autoDetect": true, "bypass": "", "enabled": false, "flags": 9, "server": ""}
original registry: {"ProxyEnable": 0, "ProxyServer": null, "ProxyOverride": null, "AutoConfigURL": null}
registry while on: {"ProxyEnable": 1, "ProxyServer": "127.0.0.1:51594", "ProxyOverride": "<local>", "AutoConfigURL": null}
child urllib.getproxies(): {'http': 'http://127.0.0.1:51594', 'https': 'http://127.0.0.1:51594', 'ftp': 'http://127.0.0.1:51594'}
```
- 프로세스 귀속: 테스트가 직접 띄운 curl 의 PID(6852)·exe 경로·명령줄·부모(테스트 자신, 9728)가 기록과 일치.
  같은 curl 의 CONNECT flow 와 그 안의 요청, HTTP/2 스트림 3개, 다른 클라이언트(python.exe 자식)도 각자의 PID 로 기록.
- 시스템 프록시: 켜면 WinINET 과 레지스트리가 바뀌고, **프록시 인자 없이** 실행한 Python urllib 요청이 WireScope 를 거쳐
  그 자식 PID 로 기록됨. 끄기 / 프록시 중지 / 강제 종료(TerminateProcess) 뒤 재시작의 "Restore" 세 경로 모두 원래 값(`flags=9`)으로 돌아옴.
- 한글 `--data` 경로: CA 파일이 정확히 그 폴더에 생김.

`integration` 이 남긴 원자료:
```text
recorded: [('localhost:51434', 'error', 'client ended TLS before the first request: TLS read failed: connection reset by peer (WSAECONNRESET 10054)'),
           ('localhost:51435', 'complete', '')]          ← 두 번째(h2 ALPN): 출력엔 없지만 검사가 통과했으므로 clientClosed 필드가 있었다
capture: available=False interfaces=0 error='Npcap is not installed. Install Npcap with loopback support, then restart WireScope.'
```
- CA 를 안 믿는 curl(LibreSSL)은 macOS curl 과 달리 TLS alert 없이 끝냈다: HTTP/1.1 은 TCP 리셋, h2 는 alert 없는 종료(위 추론).
- 거부된 upstream 감지: 2.0초 ([run 38747992427](https://github.com/andy6609/Andy-fiddler/actions/runs/38747992427) 의 integration 출력). (Windows 가 닫힌 포트에 SYN 을 몇 번 다시 보내는 것으로 알려진 시간대. 패킷으로 확인하지는 않았다)
  수정 전 코드는 writefds 만 봐서 10초 마감까지 돌았을 것이다 — 이 "수정 전" 동작은 Windows 에서 직접 재 보지는 않았다 (5절 1번은 예방 수정).

---

## 4. 확인하지 못한 것 (그대로 남김)

| 항목 | 이유 | 하려면 |
|---|---|---|
| Npcap 라이브 캡처 (loopback 포함), `pcap_stat` 실제 값 | 러너에 Npcap 없음 (무료판은 무인 설치 불가). 구조체는 SDK 1.16 헤더와 대조만 함 | 실제 PC 에 Npcap 설치 후 캡처 시작, drop 수 확인 |
| 인증서 신뢰 설치/삭제 (`CertAddCertificateContextToStore`, 현재 사용자 ROOT) | 현재 사용자 ROOT 추가는 확인 대화상자를 띄운다 → 무인 러너에서 안 돌림 | 실제 PC 에서 Certificate → Install, Edge 로 HTTPS 확인 후 Remove |
| 브라우저(Edge/Chrome)가 시스템 프록시를 따르는지 | Chromium 은 loopback 을 프록시로 안 보내서 로컬 테스트 서버로는 확인 불가 | 실제 PC 에서 외부 사이트로 |
| 관리자 권한 프로세스의 귀속 (OpenProcess 실패 경로) | 러너가 이미 관리자 | 일반 권한 WireScope + 관리자 권한 앱 |
| 실제 AI 클라이언트 (Claude Code, Codex CLI, Gemini CLI, 데스크톱 앱) | 이번 범위 밖 | 인수인계 9절 4번 |
| Windows 10/11 데스크톱, 한국어 로캘(CP949) | 러너는 Server 2025 영어 로캘 | 실제 PC |

---

## 5. Windows 에서만 다르게 동작한 것 (발견 → 수정)

"CI 에서 발견" = 러너에서 실제로 실패했고 고친 뒤 통과한 것. "예방" = 코드를 읽고 먼저 고친 것 (고치기 전 실패를 직접 보지는 않음).

| # | 증상 | 원인 | 수정 | 근거 |
|---|---|---|---|---|
| 1 | 거부된 upstream 이 10초 타임아웃까지 기다림 | Windows 는 non-blocking `connect` 실패를 `select` 의 **exceptfds** 로만 알린다 (POSIX 는 writefds) | writefds 와 exceptfds 를 같이 감시 | 예방 + 테스트 "6초 미만" 이 Windows 에서 통과 |
| 2 | `--data C:\Users\홍길동\...` 이 깨질 수 있음 | `argv` 는 ANSI 코드 페이지 (한국어 Windows = CP949, 러너 = cp1252) | `CommandLineToArgvW` 로 UTF-16 을 다시 읽어 UTF-8 로, 경로는 `u8path` | 예방 |
| 2b | 한글 `--data` 에서 엔진은 뜨는데 CA 생성이 실패 | 2번을 고친 뒤에도 `tls.cpp` 가 `create_directories(std::string)` — `path(std::string)` 은 Windows 에서 ANSI 로 해석돼 엉뚱한 이름의 폴더가 생김 | `utf8Path(directory)` | CI 에서 발견 (한글 경로 테스트가 중간에 멈춤 → 수정) |
| 3 | (MSVC 에서 컴파일 불가 예상) | nghttp2 의 옛 콜백 API 는 `ssize_t` 를 쓰는데 MSVC 에는 `ssize_t` 가 없다 | `NGHTTP2_NO_SSIZE_T` + `nghttp2_ssize` API(1.60+) | 예방. MSVC 빌드 통과 |
| 4 | Npcap 통계 구조체 크기 불일치 | Windows `pcap_stat` 은 필드 6개 (`ps_capt/ps_sent/ps_netdrop`) | SDK 1.16 헤더대로 선언 | 헤더 대조만. 실행 미검증 |
| 5 | 콘솔 창 X 로 닫으면 정리 없이 종료 | `CTRL_CLOSE_EVENT` 는 핸들러가 돌아오면 곧 프로세스를 끝낸다 | 핸들러가 정리(시스템 프록시 복원 등) 끝날 때까지 최대 4.5초 대기 | 예방. 미검증 |
| 6 | lab 프로그램이 뜨자마자 죽음 | MSVC CRT 에는 줄 버퍼링(`_IOLBF`)이 없고, `setvbuf(..., _IOLBF, 0)` 의 크기 0 을 invalid parameter 로 보고 **종료** | Windows 는 `_IONBF` | CI 에서 발견 (lab v1 실패 → 통과) |
| 7 | lab v2 `--mitm` 이 listen 전에 끝남 | 앱의 `FILE*` 를 OpenSSL DLL 의 `PEM_write_X509(FILE*)` 에 넘김 (C 런타임이 달라 `OPENSSL_Applink` 중단) | 메모리 BIO + C++ 스트림 (본체 `tls.cpp` 와 같은 방식) | CI 에서 발견 (프로그램 쪽 변경은 이것뿐인데 다음 실행에서 v2 MITM 통과. 중단 메시지 자체는 로그를 못 받아 직접 보지 못함) |
| 8 | lab v5 의 복원 바이트가 원본과 다름 | CRT 텍스트 모드 stdout 이 `\n` 을 `\r\n` 으로 바꿔 `\r\n` → `\r\r\n` | `_setmode(_fileno(stdout), _O_BINARY)` | CI 에서 발견 (이 변경 뒤 v5 확인 통과) |
| 8b | CA 를 안 믿는 클라이언트가 '정상 터널'처럼 기록됨 (오류 없음) | macOS curl 은 거부를 `SSL_accept` 중 `tlsv1 alert unknown ca` 로 보낸다. 러너의 curl(LibreSSL 4.3)은 `SSL_accept` 가 끝난 뒤 **alert 없이** 연결을 끊었다 (본체 기록: HTTP/1.1 은 첫 읽기 실패, h2 는 스트림 없이 종료). 그 경로를 아무도 기록하지 않았음 | 본체: TLS 읽기 오류에 OpenSSL 이유 또는 OS 소켓 오류(WSAECONNRESET 등), alert 없는 종료는 `clientClosed` 필드. lab v2: 요청 전 `SSL_peek` 로 같은 구분 | CI 에서 발견 (lab v2, 그다음 본체 integration 테스트) |
| 9 | MSVC /W4 경고 5개 | 멤버를 가리는 지역 이름, httplib 지역 변수와 겹치는 전역 이름, 상수 잘림 캐스트 | 이름 변경, 리터럴 | CI 에서 발견 → 0개 |
| 10 | 테스트: HTTPS/HTTP2 확인 실패 | 러너의 curl(System32, Git)이 Schannel 전용 — HTTP/2 없음, 로컬 CA 폐기 확인 실패 | curl.se 공식 Windows 빌드 사용 | CI 에서 발견 (테스트 도구) |
| 11 | 테스트: 한국어 로그 출력에서 `UnicodeEncodeError` | Windows 파이프의 Python stdout 은 ANSI(cp1252) | `sys.stdout.reconfigure(encoding="utf-8")` | CI 에서 발견 (테스트 도구) |
| 12 | provenance CLI 가 아무것도 출력하지 않음 → 실험 dry run 이 JSON 파싱 오류로 멈춤 | `new URL(import.meta.url).pathname` 은 Windows 에서 `/D:/a/...` — 경로가 아니라서 `provenance.js` 를 못 읽음 | `createRequire` 의 상대 경로 `require('../web/provenance.js')` | CI 에서 발견 ([run 38879354808](https://github.com/andy6609/Andy-fiddler/actions/runs/38879354808), `f0aabba`) → 수정 후 통과 |
| 13 | (12번을 고친 뒤, 출력에 `←` 나 한글이 있으면) `summary.txt`·stdout 에서 `UnicodeDecodeError` | Python 이 node 의 UTF-8 출력을 cp1252 로 읽고 씀. `←` 의 0x90, 한글 일부의 0x8D 등은 cp1252 에 없는 바이트 | `run_agent.py`·dry run 테스트에서 subprocess·파일·stdout 모두 UTF-8 명시, 테스트가 `→` 가 그대로인지 확인 | 예방 (12번에 가려 직접 보지 못함). macOS 에서 ISO-8859-1 로캘로 흉내 내면 latin-1 이 모든 바이트를 받아서 **통과해 버린다** — 흉내로는 못 잡는 종류 |

---

## 6. 설계 메모

### 프로세스 귀속 (`src/process.cpp`)
- 프록시가 `accept` 한 직후, **첫 바이트를 읽기 전에** `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_CONNECTIONS)` 으로
  (local = 앱 쪽 주소, remote = 프록시 주소) 줄을 찾는다. loopback 연결은 표에 양 끝이 한 줄씩 있다.
- PID → exe 이름/부모는 Toolhelp(권한 불필요), 경로는 `QueryFullProcessImageNameW`, 명령줄은 `NtQueryInformationProcess`.
- 같은 연결에서 나온 모든 flow(CONNECT, 그 안의 요청, HTTP/2 스트림 전부, 오류 flow)가 같은 기록을 갖는다.
- 목록(폴링)에는 `{pid, name}` 만, 상세·저장 파일에는 전체. 명령줄이 길어 수천 개 flow 를 매번 보내지 않으려고.
- 한계: 조회 시점의 사진, PID 재사용, IPv4 표만(프록시가 127.0.0.1 에만 listen), 패킷 캡처와는 아직 연결 안 함.

### 시스템 프록시 (`src/sysproxy.cpp`)
- `InternetSetOptionW(INTERNET_OPTION_PER_CONNECTION_OPTION)` 로 LAN 설정의 flags/server/bypass/PAC 를 바꾸고
  `SETTINGS_CHANGED` + `REFRESH` 로 떠 있는 앱에 알린다. 레지스트리를 직접 쓰지 않는다 (테스트가 결과만 읽어 확인).
- 바꾸기 전에 `%LOCALAPPDATA%\WireScope\system-proxy-backup.json` 을 쓰고, 이미 있으면 덮지 않는다.
- 되돌리는 길: 버튼 끄기, 프록시 중지(먼저 복원 후 중지), 정상 종료, 콘솔 닫기, 다음 실행의 "Restore original".
- 켤 때 PAC 와 자동 감지(WPAD)는 끈다 (남아 있으면 수동 프록시보다 먼저 쓰일 수 있다). 복원 때 원래 flags 로.

---

## 7. 다음 단계
1. 실제 Windows 데스크톱에서: Npcap(loopback) 캡처 → 같은 요청의 패킷 탭, 인증서 Install/Remove, Edge + 시스템 프록시.
2. 같은 작업을 Claude Code / Codex CLI / Gemini CLI / 데스크톱 앱으로 실행하고 Process 열 + 비교 화면으로 정리 (인수인계 9절 4번).
3. 캡처한 패킷에도 프로세스를 붙이기 (UDP 는 `GetExtendedUdpTable`, 짧은 연결은 ETW 가 필요할 수 있음).
4. ~~이 브랜치를 main 에 합칠 때: README 3줄(C++20/17) 충돌은 `windows` 쪽을 택한다.~~ 2026-10-16 그렇게 합쳤다.
