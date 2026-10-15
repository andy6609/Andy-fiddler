// Windows 시스템 프록시 켜기/복원. 설명은 sysproxy.hpp.
//
// 쓰는 API: InternetQueryOptionW / InternetSetOptionW(INTERNET_OPTION_PER_CONNECTION_OPTION)
//   - pszConnection = nullptr -> "LAN 연결" (보통 쓰는 그 설정)
//   - 바꾼 뒤 INTERNET_OPTION_SETTINGS_CHANGED + INTERNET_OPTION_REFRESH 로 실행 중인 앱들에 알린다.
// 레지스트리(HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings)를 직접 쓰지 않는 이유:
//   WinINET 은 Connections\DefaultConnectionSettings 라는 이진 값도 함께 관리하고, 직접 쓰면 알림도 안 간다.
//   (값이 레지스트리에 실제로 반영되는지는 tests/windows_test.py 가 winreg 로 따로 확인한다)
#include "sysproxy.hpp"
#include <filesystem>
#include <fstream>
#include <stdexcept>

#ifdef _WIN32
#include <windows.h>
#include <wininet.h>
#endif

namespace ws {

#ifdef _WIN32
namespace {
const char* BACKUP = "system-proxy-backup.json";

std::filesystem::path backupPath(const std::string& directory) { return utf8Path(directory) / BACKUP; }

json readBackup(const std::string& directory) {
    std::ifstream f(backupPath(directory), std::ios::binary);
    if (!f) return nullptr;
    try {
        return json::parse(f);
    } catch (...) {
        return nullptr;
    }
}

std::string utf8(const wchar_t* w) {
    if (!w || !*w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string out(size_t(n > 1 ? n - 1 : 0), '\0');
    if (n > 1) WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), n, nullptr, nullptr);
    return out;
}
std::wstring wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
    std::wstring out(size_t(n > 0 ? n : 0), L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), out.data(), n);
    return out;
}

// 현재 설정 읽기. FLAGS_UI(Windows 7+)는 사용자가 화면에서 보는 그대로의 플래그(자동 감지 포함)다.
json readSettings() {
    INTERNET_PER_CONN_OPTIONW options[4]{};
    options[0].dwOption = INTERNET_PER_CONN_FLAGS_UI;
    options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    options[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
    INTERNET_PER_CONN_OPTION_LISTW list{};
    list.dwSize = sizeof(list);
    list.pszConnection = nullptr;
    list.dwOptionCount = 4;
    list.pOptions = options;
    DWORD size = sizeof(list);
    if (!InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &size)) {
        options[0].dwOption = INTERNET_PER_CONN_FLAGS;  // FLAGS_UI 를 모르는 오래된 WinINET
        size = sizeof(list);
        if (!InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &size))
            throw std::runtime_error("InternetQueryOption failed (" + std::to_string(GetLastError()) + ")");
    }
    DWORD flags = options[0].Value.dwValue;
    json out = {{"flags", flags},
                {"enabled", (flags & PROXY_TYPE_PROXY) != 0},
                {"autoDetect", (flags & PROXY_TYPE_AUTO_DETECT) != 0},
                {"server", utf8(options[1].Value.pszValue)},
                {"bypass", utf8(options[2].Value.pszValue)},
                {"autoConfigUrl", utf8(options[3].Value.pszValue)}};
    for (int i = 1; i < 4; ++i)  // 문자열은 WinINET 이 GlobalAlloc 으로 준다
        if (options[i].Value.pszValue) GlobalFree(options[i].Value.pszValue);
    return out;
}

void writeSettings(DWORD flags, const std::string& server, const std::string& bypass, const std::string& autoConfigUrl) {
    std::wstring s = wide(server), b = wide(bypass), a = wide(autoConfigUrl);
    INTERNET_PER_CONN_OPTIONW options[4]{};
    options[0].dwOption = INTERNET_PER_CONN_FLAGS_UI;
    options[0].Value.dwValue = flags;
    options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
    options[1].Value.pszValue = s.data();
    options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
    options[2].Value.pszValue = b.data();
    options[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
    options[3].Value.pszValue = a.data();
    INTERNET_PER_CONN_OPTION_LISTW list{};
    list.dwSize = sizeof(list);
    list.pszConnection = nullptr;
    list.dwOptionCount = 4;
    list.pOptions = options;
    if (!InternetSetOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list))) {
        options[0].dwOption = INTERNET_PER_CONN_FLAGS;
        if (!InternetSetOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, sizeof(list)))
            throw std::runtime_error("InternetSetOption failed (" + std::to_string(GetLastError()) + ")");
    }
    // 이미 떠 있는 앱(브라우저 등)이 새 값을 다시 읽게 한다.
    InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
    InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
}
}  // namespace
#endif

SystemProxy::SystemProxy(std::string dataDirectory) : directory_(std::move(dataDirectory)) {}

SystemProxy::~SystemProxy() {
    try {
        if (owned()) restore();
    } catch (...) {
        // 소멸자에서는 던지지 않는다. 백업 파일이 남아 다음 실행이 복원을 권한다.
    }
}

bool SystemProxy::owned() const {
    std::lock_guard lock(mutex_);
    return enabledThisRun_;
}

json SystemProxy::status() const {
#ifdef _WIN32
    std::lock_guard lock(mutex_);
    json out = {{"supported", true}, {"ownedByWireScope", enabledThisRun_}};
    try {
        out["current"] = readSettings();
    } catch (const std::exception& e) {
        out["error"] = e.what();
    }
    auto backup = readBackup(directory_);
    out["backup"] = backup;
    // 백업이 있는데 이번 실행이 켠 게 아니다 = 이전 실행이 되돌리지 못하고 끝났다.
    out["leftover"] = !backup.is_null() && !enabledThisRun_;
    out["backupPath"] = [&] { auto u = backupPath(directory_).u8string(); return std::string(u.begin(), u.end()); }();
    return out;
#else
    return {{"supported", false}, {"error", "System proxy control is implemented for Windows only"}};
#endif
}

void SystemProxy::enable(uint16_t port) {
#ifdef _WIN32
    std::lock_guard lock(mutex_);
    auto current = readSettings();
    std::filesystem::create_directories(utf8Path(directory_));
    // 백업이 이미 있으면 덮지 않는다: 그 파일이 WireScope 를 켜기 전의 진짜 원래 값이다.
    if (readBackup(directory_).is_null()) {
        json backup = current;
        backup["savedAt"] = nowMs();
        backup["proxyPort"] = port;
        std::ofstream f(backupPath(directory_), std::ios::binary | std::ios::trunc);
        f << backup.dump(2);
        if (!f) throw std::runtime_error("Cannot write the system proxy backup file; nothing was changed");
    }
    std::string bypass = "<local>";  // 점 없는 호스트 이름은 직접. (WinINET 은 loopback 을 원래 직접 보낸다)
    writeSettings(PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY, "127.0.0.1:" + std::to_string(port), bypass, "");
    enabledThisRun_ = true;
#else
    (void)port;
    throw std::runtime_error("System proxy control is implemented for Windows only");
#endif
}

void SystemProxy::restore() {
#ifdef _WIN32
    std::lock_guard lock(mutex_);
    auto backup = readBackup(directory_);
    if (backup.is_null()) {
        enabledThisRun_ = false;
        throw std::runtime_error("No system proxy backup to restore");
    }
    writeSettings(DWORD(backup.value("flags", 1)), backup.value("server", ""), backup.value("bypass", ""), backup.value("autoConfigUrl", ""));
    std::error_code ignored;
    std::filesystem::remove(backupPath(directory_), ignored);
    enabledThisRun_ = false;
#else
    throw std::runtime_error("System proxy control is implemented for Windows only");
#endif
}

}  // namespace ws
