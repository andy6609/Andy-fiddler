/*
============================================================
 v9_win_owner  —  이 연결은 '어느 프로세스'가 열었나 (Windows)
============================================================
 목적: v1~v3 프록시는 요청 내용은 다 보지만 "누가 보냈는지"는 모른다.
       같은 PC 의 curl, node(Claude Code / Gemini CLI), python, 브라우저가 전부
       똑같이 127.0.0.1:18080 으로 들어오기 때문이다.
       Fiddler 의 Process 열처럼, 연결 하나를 프로세스 하나에 붙여 본다.

 핵심: 소켓 자체에는 "내 주인 PID" 정보가 없다. 대신 OS 가 관리하는 'TCP 연결 표'가 있다.
       Windows: GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)
                -> 줄마다 local 주소:포트, remote 주소:포트, 상태, owning PID
       (netstat -ano 가 보여 주는 바로 그 표다)

 loopback 연결은 표에 '두 줄'로 있다:
     local 127.0.0.1:52344  remote 127.0.0.1:18080  ESTABLISHED  pid = curl
     local 127.0.0.1:18080  remote 127.0.0.1:52344  ESTABLISHED  pid = 프록시 자신
   프록시는 accept 한 소켓의 상대 주소(52344)를 안다
   -> "local=52344, remote=18080" 인 줄을 찾으면 그 PID 가 보낸 프로그램이다.

 [v9 단계 1]
     v9_win_owner                 TCP 연결 표 전체 (상태, local -> remote, pid, exe)
     v9_win_owner --port 443      local 이나 remote 포트가 443 인 줄만
 [v9 단계 2]
     v9_win_owner --self          자기 자신에게 loopback 연결을 하나 만들고, 프록시가 하는 조회를 그대로 재현:
                                  accept 한 소켓의 상대 주소 -> 표에서 client 쪽 줄 -> PID -> exe

 PID -> 프로그램:
   CreateToolhelp32Snapshot  모든 프로세스의 exe 이름 + 부모 PID. 권한 없이 된다.
   OpenProcess + QueryFullProcessImageNameW  exe 전체 경로. 관리자 권한 프로세스는 실패할 수 있다.

 [이전 버전 → 이번 버전 변화]
   v1~v8 : 무엇이 오갔나 (요청 / 패킷 / 바이트)
   v9    : 누가 보냈나 (OS 의 연결 표). 내용은 하나도 안 본다.

 함정:
   - 표는 조회한 '순간'의 사진이다. curl 한 번 같은 짧은 연결은 끝나면 사라진다.
     -> 본체는 accept 직후, 첫 바이트를 읽기 전에 조회한다.
   - 포트는 DWORD 의 아래 16비트에 '네트워크 바이트 순서'로 들어 있다.
     ntohs 를 빼먹으면 443 이 47873 으로 보인다. (위 16비트는 쓰레기일 수 있다고 문서에 있다)
   - PID 는 재사용된다. 부모 PID 가 가리키는 프로세스는 이미 다른 프로그램일 수 있다.
   - 표를 두 번 부르는 사이에도 연결이 늘어난다 -> ERROR_INSUFFICIENT_BUFFER 면 크기를 늘려 다시.

 한계: IPv4 표만 (IPv6 는 AF_INET6 로 같은 방식). UDP 는 GetExtendedUdpTable 인데 remote 가 없다.
       macOS 는 `lsof -i -n -P`, Linux 는 `ss -tnp` 가 같은 표를 보여 준다 (이 프로그램은 Windows 전용).

 본체: src/process.cpp — accept 직후 한 번 조회해서 flow.process 에 기록, 화면의 Process 열.
============================================================
*/

#include <cstdio>

#ifndef _WIN32
int main() {
    std::puts("v9_win_owner: Windows 전용 (GetExtendedTcpTable). macOS 는 `lsof -i -n -P`, Linux 는 `ss -tnp` 로 같은 표를 볼 수 있다.");
    return 0;
}
#else

#include <cstring>
#include <string>

#include "lab_net.hpp"

#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>

#include <map>
#include <vector>

// 표의 한 줄을 사람이 읽을 모양으로
struct Row {
    DWORD state = 0;
    std::string local, remote;
    uint16_t localPort = 0, remotePort = 0;
    DWORD pid = 0;
};

static const char* stateName(DWORD s) {
    static const char* names[] = {"?", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT1",
                                  "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB"};
    return s < sizeof(names) / sizeof(names[0]) ? names[s] : "?";
}

static std::string ipv4(DWORD address) {  // address 는 네트워크 바이트 순서 그대로
    char text[INET_ADDRSTRLEN]{};
    IN_ADDR a{};
    a.s_addr = address;
    inet_ntop(AF_INET, &a, text, sizeof(text));
    return text;
}

static std::vector<Row> tcpTable() {
    std::vector<unsigned char> buffer(64 * 1024);
    for (int attempt = 0; attempt < 4; ++attempt) {
        DWORD size = DWORD(buffer.size());
        DWORD r = GetExtendedTcpTable(buffer.data(), &size, TRUE /* 주소 순 정렬 */, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (r == ERROR_INSUFFICIENT_BUFFER) {
            buffer.resize(size + 16 * 1024);  // 그 사이 늘어난 연결 몫까지 여유
            continue;
        }
        if (r != NO_ERROR) {
            std::printf("GetExtendedTcpTable 실패: %lu\n", r);
            return {};
        }
        auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        std::vector<Row> rows;
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& t = table->table[i];
            Row row;
            row.state = t.dwState;
            row.localPort = ntohs(u_short(t.dwLocalPort & 0xFFFF));    // 아래 16비트, 네트워크 순서 -> 호스트 순서
            row.remotePort = ntohs(u_short(t.dwRemotePort & 0xFFFF));
            row.local = ipv4(t.dwLocalAddr) + ":" + std::to_string(row.localPort);
            row.remote = ipv4(t.dwRemoteAddr) + ":" + std::to_string(row.remotePort);
            row.pid = t.dwOwningPid;
            rows.push_back(row);
        }
        return rows;
    }
    return {};
}

static std::string utf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), nullptr, 0, nullptr, nullptr);
    std::string out(size_t(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), out.data(), n, nullptr, nullptr);
    return out;
}

// pid -> (exe 이름, 부모 pid). 권한 없이 모든 프로세스가 나온다.
struct Proc {
    std::string name;
    DWORD parent = 0;
};
static std::map<DWORD, Proc> processes() {
    std::map<DWORD, Proc> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W e{};
    e.dwSize = sizeof(e);
    for (BOOL ok = Process32FirstW(snap, &e); ok; ok = Process32NextW(snap, &e))
        out[e.th32ProcessID] = {utf8(e.szExeFile), e.th32ParentProcessID};
    CloseHandle(snap);
    return out;
}

// exe 전체 경로. 실패하면 이유(에러 번호)를 그대로 보여 준다.
static std::string exePath(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "(OpenProcess 실패 " + std::to_string(GetLastError()) + ")";
    wchar_t path[32768];
    DWORD size = 32768;
    std::string out = QueryFullProcessImageNameW(h, 0, path, &size) ? utf8(std::wstring(path, size)) : "(경로 조회 실패)";
    CloseHandle(h);
    return out;
}

static void printRow(const Row& r, const std::map<DWORD, Proc>& procs) {
    auto it = procs.find(r.pid);
    std::printf("%-12s %-22s -> %-22s pid %-6lu %s\n", stateName(r.state), r.local.c_str(), r.remote.c_str(), r.pid,
                it != procs.end() ? it->second.name.c_str() : "?");
}

// [단계 2] 프록시가 하는 조회를 자기 자신으로 재현
static int selfDemo() {
    sock_t listener = lab::listenLocal(0);  // 0 = OS 가 빈 포트를 고른다
    if (listener == BAD_SOCK) return std::puts("listen 실패"), 1;
    std::string proxyEnd = lab::endpointOf(listener, false);
    uint16_t proxyPort = uint16_t(std::stoi(proxyEnd.substr(proxyEnd.rfind(':') + 1)));
    sock_t client = lab::connectTo("127.0.0.1", proxyPort);  // '앱' 역할
    sock_t accepted = accept(listener, nullptr, nullptr);     // '프록시' 역할
    if (client == BAD_SOCK || accepted == BAD_SOCK) return std::puts("loopback 연결 실패"), 1;

    // 프록시가 아는 것은 accept 한 소켓의 상대 주소뿐이다.
    std::string peer = lab::endpointOf(accepted, true);
    std::printf("[self] 프록시 listen   : %s\n", proxyEnd.c_str());
    std::printf("[self] accept 한 상대  : %s   <- 이걸로 표를 찾는다\n\n", peer.c_str());

    auto procs = processes();
    DWORD found = 0;
    for (const auto& r : tcpTable()) {
        bool clientSide = r.local == peer && r.remote == proxyEnd;  // 앱 쪽 줄
        bool proxySide = r.local == proxyEnd && r.remote == peer;   // 프록시 쪽 줄
        if (!clientSide && !proxySide) continue;
        std::printf("%s ", clientSide ? "[client row]" : "[proxy row] ");
        printRow(r, procs);
        if (clientSide) found = r.pid;
    }
    std::printf("\n[self] client 쪽 줄의 owning pid = %lu, 이 프로그램의 pid = %lu  (%s)\n", found, GetCurrentProcessId(),
                found == GetCurrentProcessId() ? "같음: 이 데모에선 앱과 프록시가 같은 프로세스" : "다름");
    if (found) std::printf("[self] exe 경로 = %s\n", exePath(found).c_str());
    lab::closeSock(client);
    lab::closeSock(accepted);
    lab::closeSock(listener);
    return found == GetCurrentProcessId() ? 0 : 1;
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);  // 한국어 출력이 콘솔에서 깨지지 않게
    lab::netInit();
    if (argc > 1 && std::strcmp(argv[1], "--self") == 0) return selfDemo();

    int port = -1;
    if (argc > 2 && std::strcmp(argv[1], "--port") == 0) port = std::atoi(argv[2]);
    auto procs = processes();
    int shown = 0;
    for (const auto& r : tcpTable()) {
        if (port >= 0 && r.localPort != port && r.remotePort != port) continue;
        printRow(r, procs);
        ++shown;
    }
    std::printf("-- %d rows (IPv4 TCP, GetExtendedTcpTable TCP_TABLE_OWNER_PID_ALL)\n", shown);
    return 0;
}
#endif
