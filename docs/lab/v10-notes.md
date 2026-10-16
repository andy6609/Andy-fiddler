# v10 노트 — Windows 의 프록시 설정은 세 군데

> 코드: `lab/v10_win_sysproxy/v10_win_sysproxy.cpp` (Windows 전용)
> 실행: `v10_win_sysproxy.exe` (읽기만) / `... --set 18080` / `... --restore`

---

## 1. v1~v3 대비 변화

| | v1~v3 | v10 |
|---|---|---|
| 클라이언트에게 프록시 알리기 | 직접 (`curl -x`) | OS 설정으로 간접 |
| 장점 | 확실하다 | 앱마다 설정하지 않아도 된다 |
| 단점 | 앱마다 해야 한다 | **따르는 앱과 안 따르는 앱이 갈린다** |

---

## 2. ★ 꼭 이해하고 갈 것

### (A) 세 군데
| 설정 | 범위 | 바꾸는 곳 | 읽는 쪽 (대표) |
|---|---|---|---|
| WinINET | 현재 사용자 | 설정 > 프록시, `inetcpl.cpl` | Edge/Chrome, 대부분의 데스크톱 앱, .NET, Python urllib |
| WinHTTP | 기기 전체 | `netsh winhttp set proxy` | Windows 서비스, 업데이트, 일부 백그라운드 에이전트 |
| 환경 변수 | 그 프로세스와 자식 | `$env:HTTPS_PROXY=...` | curl, Node.js CLI (Claude Code, Codex, Gemini CLI), git, pip |

→ "시스템 프록시를 켰는데 CLI 에이전트 요청이 안 보인다" 는 버그가 아니라 세 번째 칸을 안 써서다.
   Node.js 기반 CLI 는 프록시 외에 CA 도 따로 알려 줘야 한다 (`NODE_EXTRA_CA_CERTS`).

### (B) WinINET 은 API 로 쓰고, 알린다
```
InternetSetOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, ...)  // flags, server, bypass, PAC
InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0)        // 떠 있는 앱들아 다시 읽어
InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0)
```
- 레지스트리(`HKCU\...\Internet Settings` 의 `ProxyEnable/ProxyServer`)를 직접 쓰면 이미 떠 있는 앱은 모른다.
  또 WinINET 은 `Connections\DefaultConnectionSettings` 라는 이진 값도 같이 관리한다.
- 그래도 레지스트리 값은 **결과 확인용**으로 읽는다. Python urllib 처럼 API 대신 그 값을 직접 읽는 프로그램이 있기 때문.

### (C) 켜기 전에 백업, 되돌리기는 여러 길로
`--set` 은 바꾸기 **전에** 원래 값을 `v10-proxy-backup.json` 에 쓴다. 백업이 이미 있으면 덮지 않는다
(그 파일이 "켜기 전" 진짜 원래 값이니까). 프로그램이 죽어도 파일이 남아 다음에 `--restore` 할 수 있다.
본체는 여기에 더해 **끄기 / 프록시 중지 / 정상 종료 / 콘솔 창 닫기** 때 자동으로 되돌리고,
비정상 종료 뒤 다음 실행에서 남은 백업을 찾으면 화면에 "Restore original" 을 띄운다.

### (D) 켤 때 PAC 와 자동 감지를 끄는 이유
flags 에 `AUTO_PROXY_URL`(PAC) 이나 `AUTO_DETECT`(WPAD) 가 남아 있으면 그쪽이 수동 프록시보다 먼저 쓰일 수 있다.
그래서 켤 때는 `DIRECT | PROXY` 만 남기고, 되돌릴 때 백업의 flags 를 그대로 복원한다
(러너의 원래 값은 `flags=9` = DIRECT + AUTO_DETECT 였다).

### (E) 헤더 충돌
`winhttp.h` 와 `wininet.h` 는 한 파일에 같이 include 할 수 없다 (같은 이름의 타입/매크로).
v10 은 WinHTTP 함수 하나(`WinHttpGetDefaultProxyConfiguration`)만 `LoadLibrary + GetProcAddress` 로 부르고
구조체(`WINHTTP_PROXY_INFO`)는 직접 선언했다.

---

## 3. 🟡 단순화한 것
- WinINET 의 "LAN 설정"(`pszConnection = nullptr`)만 다룬다. 전화 접속/VPN 연결별 설정은 안 본다.
- bypass 는 `<local>` 하나. Chrome/Edge 는 loopback 을 원래 프록시로 보내지 않으므로, 127.0.0.1 대상 테스트를
  브라우저로 보려면 bypass 에 `<-loopback>` 이 필요하다 (v10 은 안 넣음).
- WinHTTP 설정은 읽기만 한다 (쓰려면 관리자 권한 + 기기 전체에 영향).

---

## 4. 확인한 것 / 못 한 것

확인 방법은 GitHub Actions `windows-latest` 러너의 `tests/lab_smoke.py` (v10) 와 `tests/windows_test.py` (본체).
결과는 [docs/WINDOWS.md](../WINDOWS.md) 에 실행 번호와 함께 적는다.

- 세 구역 출력, 테스트가 넘긴 환경 변수가 3번 구역에 보임, WinHTTP 기본값 읽기
- `--set` 뒤 레지스트리 `ProxyEnable=1 / ProxyServer=127.0.0.1:18999`, `--restore` 뒤 원래 값 + 백업 파일 삭제 (CI 에서만)
- ❌ 실제 브라우저(Edge)가 바뀐 설정을 따르는지는 보지 않았다. 본체 테스트는 Python urllib 로 확인했다.
