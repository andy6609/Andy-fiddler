/*
============================================================
 v11_provenance  —  "이 파일의 어느 부분이 어느 요청에 실려 나갔나"
============================================================
 목적: v1~v8 은 요청/패킷을 '보는' 도구였다. 이번엔 출발점이 다르다.
       내 컴퓨터에 있는 '로컬 파일'에서 출발해서, 그 내용이 어느 요청 body 안에 있었는지 찾는다.
       인턴 때 질문(AI 로 파일이 어떻게 나가나)과 멘토님이 말한 파일 I/O 관점을 프록시 기록에 잇는 단계.
       WireScope 본체에서는 web/provenance.js 가 같은 일을 더 넓게 한다 (이 버전은 개념만).

 [v11 단계 1 — 이 커밋]  canary 로 시작
   canary = 실험용 파일에 일부러 심어 둔 고유한 문자열 (WSCANARY-config-1a2b ...).
   보통 문장은 여러 파일에 같이 있을 수 있지만, 무작위 토큰은 그 파일에만 있다.
   -> 요청 body 에서 그 토큰이 보이면 "그 파일에서 온 바이트" 라는 게 모호하지 않다.

     ./v11_provenance flows.jsonl ./sandbox
       1) sandbox 의 파일을 전부 읽어서 WSCANARY-... 토큰을 모은다 (토큰 -> 파일:줄)
       2) flows.jsonl (v1/v2 가 쓴 기록) 의 요청/응답 body 를 base64 에서 풀어서 토큰을 찾는다
       3) 본 것 / 한 번도 안 나온 것 / 어느 파일에도 없는데 트래픽에 있는 것 을 출력

 ★ 증명하는 것과 못 하는 것
   증명: 이 토큰(= 그 파일의 바이트)이 이 요청 body 안에 있었다 (프록시가 캡처한 범위에서).
   못 함: 어느 프로세스가 그 파일을 읽었는지, 캡처 밖(QUIC, 프록시 무시)으로 나간 게 없는지.
============================================================
*/

#include "json.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <regex>
#include <set>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using json = nlohmann::json;

// ------------------------------------------------------------
// base64 디코드 (v1 이 body 를 base64 로 기록했으니까)
// ------------------------------------------------------------
static std::string unbase64(const std::string& in) {
    static int T[256];
    static bool init = false;
    if (!init) {
        for (int& t : T) t = -1;
        const char* a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; i++) T[uint8_t(a[i])] = i;
        init = true;
    }
    std::string out;
    uint32_t buf = 0;
    int bits = 0;
    for (unsigned char c : in) {
        if (T[c] < 0) continue;
        buf = (buf << 6) | uint32_t(T[c]);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += char((buf >> bits) & 0xff);
        }
    }
    return out;
}

static std::string readAll(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return {(std::istreambuf_iterator<char>(f)), {}};
}

// 로컬 파일 하나 = 이름 + 내용
struct LocalFile {
    std::string name, content;
};

// .git 과 node_modules 는 건너뛴다 (본체의 폴더 추가와 같은 규칙), 2 MiB 넘는 파일도
static std::vector<LocalFile> readTree(const fs::path& root) {
    std::vector<LocalFile> files;
    for (auto it = fs::recursive_directory_iterator(root); it != fs::recursive_directory_iterator(); ++it) {
        const auto name = it->path().filename().string();
        if (it->is_directory() && (name == ".git" || name == "node_modules")) {
            it.disable_recursion_pending();
            continue;
        }
        if (!it->is_regular_file() || it->file_size() > 2 * 1024 * 1024) continue;
        files.push_back({fs::relative(it->path(), root).generic_string(), readAll(it->path())});
    }
    return files;
}

// body 하나 = 어느 기록의 어느 방향인지 + 바이트
struct Body {
    uint64_t flow;
    std::string side, bytes;
};

static std::vector<Body> readBodies(const std::string& jsonlPath, size_t& records) {
    std::vector<Body> bodies;
    std::ifstream in(jsonlPath);
    std::string line;
    records = 0;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        json r = json::parse(line, nullptr, false);
        if (r.is_discarded()) continue;
        records++;
        uint64_t id = r.value("id", uint64_t(records));
        for (const char* side : {"request", "response"}) {
            if (!r.contains(side) || !r[side].is_object()) continue;
            std::string bytes = unbase64(r[side].value("base64", ""));
            if (!bytes.empty()) bodies.push_back({id, side, bytes});
        }
    }
    return bodies;
}

static int lineOf(const std::string& text, size_t offset) {
    int n = 1;
    for (size_t i = 0; i < offset && i < text.size(); i++)
        if (text[i] == '\n') n++;
    return n;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("사용법: %s flows.jsonl <로컬 폴더>\n", argv[0]);
        return 1;
    }
    if (!fs::is_directory(argv[2])) {
        printf("로컬 폴더가 없음: %s\n", argv[2]);
        return 1;
    }
    size_t records = 0;
    auto bodies = readBodies(argv[1], records);
    auto files = readTree(argv[2]);
    printf("기록 %zu개, body %zu개, 로컬 파일 %zu개\n", records, bodies.size(), files.size());

    // 1) 로컬 파일에서 canary 수집: 토큰 -> "파일:줄"
    const std::regex canary("WSCANARY-[A-Za-z0-9_-]{2,64}");
    std::map<std::string, std::vector<std::string>> origin;
    for (auto& f : files)
        for (auto it = std::sregex_iterator(f.content.begin(), f.content.end(), canary); it != std::sregex_iterator(); ++it)
            origin[it->str()].push_back(f.name + ":" + std::to_string(lineOf(f.content, size_t(it->position()))));

    // 2) body 안에서 canary 찾기. body 는 JSON 이든 multipart 든 바이트 그대로 검색 (토큰은 escape 될 문자가 없음)
    printf("\nCANARIES\n");
    std::set<std::string> seen;
    for (auto& b : bodies) {
        for (auto it = std::sregex_iterator(b.bytes.begin(), b.bytes.end(), canary); it != std::sregex_iterator(); ++it) {
            const std::string token = it->str();
            seen.insert(token);
            auto o = origin.find(token);
            std::string from = o == origin.end() ? "(어느 로컬 파일에도 없음)" : o->second.front();
            printf("  본 것      %-28s  %-24s -> #%llu %s\n", token.c_str(), from.c_str(), (unsigned long long)b.flow, b.side.c_str());
        }
    }
    for (auto& [token, where] : origin)
        if (!seen.count(token)) printf("  못 본 것   %-28s  %s\n", token.c_str(), where.front().c_str());
    return 0;
}
