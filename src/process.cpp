// 연결 -> 프로세스 귀속 (Windows). 설명은 process.hpp.
//
// 쓰는 Windows API
//   GetExtendedTcpTable(TCP_TABLE_OWNER_PID_CONNECTIONS)  연결 표 + 각 줄의 owning PID   (iphlpapi)
//   CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)          PID -> exe 이름, 부모 PID      (권한 없이 됨)
//   OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)        PID -> 핸들 (관리자 권한 앱은 실패할 수 있음)
//   QueryFullProcessImageNameW                            핸들 -> exe 전체 경로
//   NtQueryInformationProcess(ProcessCommandLineInformation) 핸들 -> 명령줄 (Windows 8.1+, ntdll)
//
// 한계 (화면/문서에 그대로 밝힌다)
//   - 조회 시점의 표다. 연결이 이미 닫혔으면 못 찾는다 (그래서 accept 직후, 첫 바이트를 읽기 전에 조회).
//   - PID 는 재사용된다. 특히 parentPid 는 부모가 먼저 끝났으면 다른 프로세스를 가리킬 수 있다.
//   - 프록시 listen 소켓이 IPv4(127.0.0.1)라서 IPv4 표만 본다.
#include "process.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <vector>
#endif

namespace ws {

#ifdef _WIN32
namespace {

std::string utf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), nullptr, 0, nullptr, nullptr);
    std::string out(size_t(n > 0 ? n : 0), '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), out.data(), n, nullptr, nullptr);
    return out;
}

// "127.0.0.1:52344" -> (네트워크 바이트 순서 주소, 포트). IPv6 "[::1]:x" 는 false.
bool parseIPv4(const std::string& text, IN_ADDR& address, uint16_t& port) {
    auto colon = text.rfind(':');
    if (text.empty() || colon == std::string::npos || text.front() == '[') return false;
    if (inet_pton(AF_INET, text.substr(0, colon).c_str(), &address) != 1) return false;
    try {
        port = uint16_t(std::stoi(text.substr(colon + 1)));
    } catch (...) {
        return false;
    }
    return true;
}

// 연결 표에서 (local=client, remote=proxy) 줄을 찾아 PID 를 돌려준다. 0 = 못 찾음.
DWORD owningPid(const IN_ADDR& clientAddress, uint16_t clientPort, const IN_ADDR& proxyAddress, uint16_t proxyPort) {
    std::vector<unsigned char> buffer(64 * 1024);
    for (int attempt = 0; attempt < 4; ++attempt) {
        DWORD size = DWORD(buffer.size());
        DWORD result = GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
        if (result == ERROR_INSUFFICIENT_BUFFER) {  // 두 호출 사이에도 연결은 늘어난다 -> 여유를 두고 다시
            buffer.resize(size + 16 * 1024);
            continue;
        }
        if (result != NO_ERROR) return 0;
        auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            // 포트는 DWORD 의 아래 16비트에 네트워크 바이트 순서로 들어 있다 (위 16비트는 쓰레기일 수 있음).
            if (row.dwLocalAddr == clientAddress.s_addr && ntohs(u_short(row.dwLocalPort & 0xFFFF)) == clientPort &&
                row.dwRemoteAddr == proxyAddress.s_addr && ntohs(u_short(row.dwRemotePort & 0xFFFF)) == proxyPort)
                return row.dwOwningPid;
        }
        return 0;
    }
    return 0;
}

// Toolhelp 스냅샷: 권한 없이도 모든 프로세스의 exe 이름과 부모 PID 가 나온다.
struct Entry {
    std::wstring name;
    DWORD parent = 0;
};
bool snapshotEntry(DWORD pid, Entry& self, Entry& parent) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W e{};
    e.dwSize = sizeof(e);
    bool found = false;
    std::vector<std::pair<DWORD, std::wstring>> names;
    for (BOOL ok = Process32FirstW(snap, &e); ok; ok = Process32NextW(snap, &e)) {
        names.emplace_back(e.th32ProcessID, e.szExeFile);
        if (e.th32ProcessID == pid) {
            self.name = e.szExeFile;
            self.parent = e.th32ParentProcessID;
            found = true;
        }
    }
    CloseHandle(snap);
    for (auto& [id, name] : names)
        if (found && id == self.parent) parent.name = name;
    return found;
}

// 다른 프로세스의 명령줄. 공식 Win32 함수가 없어서 ntdll 의 NtQueryInformationProcess 를 쓴다.
// ProcessCommandLineInformation(60) 은 Windows 8.1 부터, PROCESS_QUERY_LIMITED_INFORMATION 이면 된다.
std::wstring commandLine(HANDLE process) {
    using Query = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static const auto query = reinterpret_cast<Query>(
        reinterpret_cast<void (*)()>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess")));
    if (!query) return {};
    constexpr ULONG ProcessCommandLineInformation = 60;
    ULONG length = 0;
    query(process, ProcessCommandLineInformation, nullptr, 0, &length);  // 필요한 크기만 받는다
    if (!length || length > 1024 * 1024) return {};
    std::vector<unsigned char> buffer(length);
    if (query(process, ProcessCommandLineInformation, buffer.data(), length, &length) < 0) return {};
    auto* text = reinterpret_cast<UNICODE_STRING*>(buffer.data());  // 결과 = UNICODE_STRING + 뒤에 붙은 문자열
    return std::wstring(text->Buffer, text->Length / sizeof(wchar_t));
}

}  // namespace

json processForConnection(const std::string& clientEndpoint, const std::string& proxyEndpoint) {
    json out = {{"source", "GetExtendedTcpTable at accept"}};
    IN_ADDR clientAddress{}, proxyAddress{};
    uint16_t clientPort = 0, proxyPort = 0;
    if (!parseIPv4(clientEndpoint, clientAddress, clientPort) || !parseIPv4(proxyEndpoint, proxyAddress, proxyPort)) {
        out["error"] = "not an IPv4 connection: " + clientEndpoint;
        return out;
    }
    DWORD pid = owningPid(clientAddress, clientPort, proxyAddress, proxyPort);
    if (!pid) {
        out["error"] = "no TCP table row for " + clientEndpoint + " -> " + proxyEndpoint + " (connection already closed?)";
        return out;
    }
    out["pid"] = pid;

    Entry self, parent;
    if (snapshotEntry(pid, self, parent)) {
        out["name"] = utf8(self.name);
        out["parentPid"] = self.parent;
        if (!parent.name.empty()) out["parentName"] = utf8(parent.name);
    }

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        // 예: 관리자 권한으로 실행된 앱을 일반 권한 WireScope 가 열 때 (5 = ERROR_ACCESS_DENIED)
        out["error"] = "OpenProcess failed (" + std::to_string(GetLastError()) + "); name/parent from Toolhelp only";
        return out;
    }
    std::vector<wchar_t> path(32768);
    DWORD size = DWORD(path.size());
    if (QueryFullProcessImageNameW(process, 0, path.data(), &size)) out["path"] = utf8(std::wstring(path.data(), size));
    auto line = commandLine(process);
    if (!line.empty()) out["commandLine"] = utf8(line);
    CloseHandle(process);
    return out;
}

#else

json processForConnection(const std::string&, const std::string&) { return nullptr; }

#endif

}  // namespace ws
