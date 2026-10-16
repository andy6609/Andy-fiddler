/*
============================================================
 v10_win_sysproxy  —  Windows 의 '프록시 설정'은 한 군데가 아니다
============================================================
 목적: v1~v3 에서는 curl -x 처럼 클라이언트에게 프록시를 직접 알려 줬다.
       앱마다 그렇게 할 수 없으면 OS 의 '시스템 프록시'를 쓴다. 그런데 Windows 에는
       서로 다른 프록시 설정이 적어도 세 군데 있고, 앱마다 읽는 곳이 다르다.

   ┌──────────────────────┬──────────────────────────────────────┬──────────────────────────────────────┐
   │ 설정                  │ 어디서 바꾸나 / 어디 저장되나          │ 누가 읽나 (대표)                       │
   ├──────────────────────┼──────────────────────────────────────┼──────────────────────────────────────┤
   │ 1. WinINET (사용자별) │ 설정 > 프록시, inetcpl.cpl            │ Edge/Chrome, 대부분의 데스크톱 앱,      │
   │                      │ HKCU\...\Internet Settings            │ .NET HttpClient, Python urllib          │
   │                      │  (ProxyEnable/ProxyServer/... +       │                                        │
   │                      │   Connections\DefaultConnectionSettings)│                                      │
   │ 2. WinHTTP (기기 전체)│ netsh winhttp set proxy               │ Windows 서비스, Windows Update,         │
   │                      │ HKLM\...\Connections\WinHttpSettings   │ 일부 백그라운드 에이전트                 │
   │ 3. 환경 변수 (프로세스)│ set HTTPS_PROXY=... (그 창과 자식만)   │ curl, Node.js CLI(Claude Code, Codex,  │
   │                      │                                      │ Gemini CLI), git, pip, Go 프로그램       │
   └──────────────────────┴──────────────────────────────────────┴──────────────────────────────────────┘
   => "시스템 프록시를 켰는데 CLI 에이전트 요청이 안 보인다" 는 버그가 아니라 3번을 안 써서다.

 [v10 단계 1]
     v10_win_sysproxy                  세 군데를 나란히 보여 준다 (읽기만, 아무것도 안 바꿈)
 [v10 단계 2]
     v10_win_sysproxy --set 18080      1번(WinINET)만 127.0.0.1:18080 으로. 바꾸기 전 값을 v10-proxy-backup.json 에 먼저 저장
     v10_win_sysproxy --restore        백업으로 되돌리고 백업 파일 삭제

 API:
   InternetQueryOptionW / InternetSetOptionW (INTERNET_OPTION_PER_CONNECTION_OPTION)   WinINET 읽기/쓰기
   InternetSetOptionW(INTERNET_OPTION_SETTINGS_CHANGED / REFRESH)                     떠 있는 앱들에게 "다시 읽어"
   WinHttpGetDefaultProxyConfiguration                                               WinHTTP 기본값 읽기
   RegGetValueW                                                                      WinINET 이 레지스트리에 남긴 값 확인

 [이전 버전 → 이번 버전 변화]
   v1~v3 : 클라이언트에게 프록시를 '직접' 알려 줌 (curl -x)
   v10   : OS 설정으로 '간접적으로' 알려 줌. 대신 따르는 앱과 안 따르는 앱이 갈린다.

 함정:
   - 레지스트리 값을 직접 쓰면 이미 떠 있는 앱은 모른다 -> WinINET API 로 쓰고 SETTINGS_CHANGED 로 알린다.
   - 되돌리기를 잊으면 프록시가 꺼진 뒤 브라우저가 인터넷이 안 된다 (Fiddler 가 비정상 종료됐을 때 흔한 증상).
     -> 바꾸기 '전에' 백업을 파일로 남겨, 프로그램이 죽어도 다음에 되돌릴 수 있게.
   - Chrome/Edge 는 localhost/127.0.0.1 요청을 프록시로 보내지 않는다 (bypass 에 <-loopback> 을 넣어야 함).
   - winhttp.h 와 wininet.h 는 한 파일에 같이 include 할 수 없다 (같은 이름의 타입/매크로가 충돌).
     -> 여기서는 WinHTTP 함수 하나만 LoadLibrary + GetProcAddress 로 부른다.
   - 자동 감지(WPAD)와 PAC(AutoConfigURL)가 켜져 있으면 수동 프록시보다 먼저 쓰일 수 있다 -> 켤 때 둘 다 끈다.

 본체: src/sysproxy.cpp — 같은 방식 + 프록시 중지/정상 종료 때 자동 복원 + 다음 실행에서 남은 백업 감지.
============================================================
*/

#include <cstdio>

#ifndef _WIN32
int main() {
    std::puts("v10_win_sysproxy: Windows 전용 (WinINET/WinHTTP). macOS 는 `scutil --proxy` 와 networksetup 이 비슷한 역할을 한다.");
    return 0;
}
#else

#include <cstring>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wininet.h>

#include <cstdlib>
#include <fstream>

#include "json.hpp"

using json = nlohmann::json;
static const char* BACKUP_FILE = "v10-proxy-backup.json";

static std::string utf8(const wchar_t* w) {
    if (!w || !*w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string out(size_t(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), n, nullptr, nullptr);
    return out;
}
static std::wstring wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
    std::wstring out(size_t(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), out.data(), n);
    return out;
}

// ---- 1. WinINET -----------------------------------------------------------
static std::string flagNames(DWORD f) {
    std::string out;
    if (f & PROXY_TYPE_DIRECT) out += "DIRECT ";
    if (f & PROXY_TYPE_PROXY) out += "PROXY ";
    if (f & PROXY_TYPE_AUTO_PROXY_URL) out += "AUTO_PROXY_URL(PAC) ";
    if (f & PROXY_TYPE_AUTO_DETECT) out += "AUTO_DETECT(WPAD) ";
    return out.empty() ? "(none)" : out;
}

static json readWinInet() {
    INTERNET_PER_CONN_OPTIONW o[4]{};
    o[0].dwOption = INTERNET_PER_CONN_FLAGS_UI;          // 사용자가 화면에서 보는 그대로 (Windows 7+)
    o[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    o[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    o[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
    INTERNET_PER_CONN_OPTION_LISTW list{};
    list.dwSize = sizeof(list);
    list.pszConnection = nullptr;                          // nullptr = LAN 설정 (보통 쓰는 것)
    list.dwOptionCount = 4;
    list.pOptions = o;
    DWORD size = sizeof(list);
    if (!InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &size)) {
        o[0].dwOption = INTERNET_PER_CONN_FLAGS;
        size = sizeof(list);
        if (!InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &size))
            return {{"error", "InternetQueryOption " + std::to_string(GetLastError())}};
    }
    json j = {{"flags", o[0].Value.dwValue}, {"server", utf8(o[1].Value.pszValue)}, {"bypass", utf8(o[2].Value.pszValue)},
              {"autoConfigUrl", utf8(o[3].Value.pszValue)}};
    for (int i = 1; i < 4; ++i)
        if (o[i].Value.pszValue) GlobalFree(o[i].Value.pszValue);  // WinINET 이 GlobalAlloc 으로 준 문자열
    return j;
}

static bool writeWinInet(DWORD flags, const std::string& server, const std::string& bypass, const std::string& pac) {
    std::wstring s = wide(server), b = wide(bypass), a = wide(pac);
    INTERNET_PER_CONN_OPTIONW o[4]{};
    o[0].dwOption = INTERNET_PER_CONN_FLAGS_UI;
    o[0].Value.dwValue = flags;
    o[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    o[1].Value.pszValue = s.data();
    o[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    o[2].Value.pszValue = b.data();
    o[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
    o[3].Value.pszValue = a.data();
    INTERNET_PER_CONN_OPTION_LISTW list{};
    list.dwSize = sizeof(list);
    list.dwOptionCount = 4;
    list.pOptions = o;
    if (!InternetSetOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list))) {
        o[0].dwOption = INTERNET_PER_CONN_FLAGS;
        if (!InternetSetOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list))) return false;
    }
    InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);  // 떠 있는 앱들에게 알림
    InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
    return true;
}

// WinINET 이 레지스트리에 남긴 '옛 방식' 값. Python urllib 같은 프로그램은 API 대신 이걸 직접 읽는다.
static std::string registryValue(const wchar_t* name) {
    const wchar_t* key = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    DWORD type = 0, size = 0;
    if (RegGetValueW(HKEY_CURRENT_USER, key, name, RRF_RT_REG_SZ | RRF_RT_REG_DWORD, &type, nullptr, &size) != ERROR_SUCCESS)
        return "(없음)";
    if (type == REG_DWORD) {
        DWORD v = 0;
        size = sizeof(v);
        RegGetValueW(HKEY_CURRENT_USER, key, name, RRF_RT_REG_DWORD, nullptr, &v, &size);
        return std::to_string(v);
    }
    std::wstring w(size / sizeof(wchar_t) + 1, L'\0');
    RegGetValueW(HKEY_CURRENT_USER, key, name, RRF_RT_REG_SZ, nullptr, w.data(), &size);
    return "\"" + utf8(w.c_str()) + "\"";
}

// ---- 2. WinHTTP (wininet.h 와 충돌하므로 winhttp.h 없이 직접 선언) -------------
struct WinHttpProxyInfo {  // = WINHTTP_PROXY_INFO
    DWORD dwAccessType;
    LPWSTR lpszProxy;
    LPWSTR lpszProxyBypass;
};

static void showWinHttp() {
    std::puts("[2] WinHTTP (기기 전체) — WinHttpGetDefaultProxyConfiguration = `netsh winhttp show proxy`");
    HMODULE m = LoadLibraryExW(L"winhttp.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    using Fn = BOOL(WINAPI*)(WinHttpProxyInfo*);
    auto get = m ? reinterpret_cast<Fn>(reinterpret_cast<void (*)()>(GetProcAddress(m, "WinHttpGetDefaultProxyConfiguration"))) : nullptr;
    WinHttpProxyInfo info{};
    if (!get || !get(&info)) {
        std::printf("    읽기 실패 (%lu)\n", GetLastError());
    } else {
        const char* type = info.dwAccessType == 1 ? "NO_PROXY (직접 연결)" : info.dwAccessType == 3 ? "NAMED_PROXY" : info.dwAccessType == 0 ? "DEFAULT_PROXY" : "?";
        std::printf("    access type  = %lu %s\n", info.dwAccessType, type);
        std::printf("    proxy        = %s\n", utf8(info.lpszProxy).c_str());
        std::printf("    bypass       = %s\n", utf8(info.lpszProxyBypass).c_str());
        if (info.lpszProxy) GlobalFree(info.lpszProxy);
        if (info.lpszProxyBypass) GlobalFree(info.lpszProxyBypass);
    }
    if (m) FreeLibrary(m);
}

// ---- 3. 환경 변수 -----------------------------------------------------------
static void showEnvironment() {
    std::puts("[3] 환경 변수 (이 프로세스와 자식만) — curl, Node.js CLI, git, pip 가 읽는 것");
    // Windows 환경 변수 이름은 대소문자를 구분하지 않는다 (https_proxy == HTTPS_PROXY). Linux 와 다른 점.
    for (const wchar_t* name : {L"HTTP_PROXY", L"HTTPS_PROXY", L"ALL_PROXY", L"NO_PROXY", L"NODE_EXTRA_CA_CERTS", L"SSL_CERT_FILE"}) {
        wchar_t value[4096];
        DWORD n = GetEnvironmentVariableW(name, value, 4096);
        std::printf("    %-20s = %s\n", utf8(name).c_str(), n && n < 4096 ? utf8(value).c_str() : "(없음)");
    }
}

static void showAll() {
    json w = readWinInet();
    std::puts("[1] WinINET (현재 사용자) — InternetQueryOption(INTERNET_PER_CONN_*)");
    if (w.contains("error")) {
        std::printf("    %s\n", w["error"].get<std::string>().c_str());
    } else {
        DWORD f = w["flags"];
        std::printf("    flags        = 0x%lx %s\n", f, flagNames(f).c_str());
        std::printf("    proxy server = %s\n", w["server"].get<std::string>().c_str());
        std::printf("    bypass       = %s\n", w["bypass"].get<std::string>().c_str());
        std::printf("    PAC url      = %s\n", w["autoConfigUrl"].get<std::string>().c_str());
    }
    std::printf("    registry     : ProxyEnable=%s ProxyServer=%s ProxyOverride=%s AutoConfigURL=%s\n",
                registryValue(L"ProxyEnable").c_str(), registryValue(L"ProxyServer").c_str(),
                registryValue(L"ProxyOverride").c_str(), registryValue(L"AutoConfigURL").c_str());
    showWinHttp();
    showEnvironment();
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    if (argc > 2 && std::strcmp(argv[1], "--set") == 0) {
        std::ifstream exists(BACKUP_FILE);
        if (!exists) {  // 이미 백업이 있으면 덮지 않는다: 그게 '켜기 전' 진짜 원래 값
            json before = readWinInet();
            if (before.contains("error")) return std::printf("%s\n", before["error"].get<std::string>().c_str()), 1;
            std::ofstream(BACKUP_FILE) << before.dump(2);
            std::printf("백업 -> %s : %s\n", BACKUP_FILE, before.dump().c_str());
        }
        std::string server = std::string("127.0.0.1:") + argv[2];
        // DIRECT|PROXY 만: PAC/WPAD 를 끄지 않으면 그쪽이 먼저 쓰일 수 있다
        if (!writeWinInet(PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY, server, "<local>", ""))
            return std::printf("InternetSetOption 실패 (%lu)\n", GetLastError()), 1;
        std::printf("WinINET -> %s (되돌리기: v10_win_sysproxy --restore)\n\n", server.c_str());
        showAll();
        return 0;
    }
    if (argc > 1 && std::strcmp(argv[1], "--restore") == 0) {
        std::ifstream f(BACKUP_FILE);
        if (!f) return std::printf("%s 없음: 되돌릴 값이 없다\n", BACKUP_FILE), 1;
        json b = json::parse(f);
        f.close();
        if (!writeWinInet(b.value("flags", 1u), b.value("server", ""), b.value("bypass", ""), b.value("autoConfigUrl", "")))
            return std::printf("InternetSetOption 실패 (%lu)\n", GetLastError()), 1;
        std::remove(BACKUP_FILE);
        std::printf("복원: %s\n\n", b.dump().c_str());
        showAll();
        return 0;
    }
    showAll();
    return 0;
}
#endif
