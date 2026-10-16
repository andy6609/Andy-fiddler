/*
============================================================
 v11_provenance  —  "이 파일의 어느 부분이 어느 요청에 실려 나갔나"
============================================================
 목적: v1~v8 은 요청/패킷을 '보는' 도구였다. 이번엔 출발점이 다르다.
       내 컴퓨터에 있는 '로컬 파일'에서 출발해서, 그 내용이 어느 요청 body 안에 있었는지 찾는다.
       인턴 때 질문(AI 로 파일이 어떻게 나가나)과 멘토님이 말한 파일 I/O 관점을 프록시 기록에 잇는 단계.
       WireScope 본체에서는 web/provenance.js 가 같은 일을 더 넓게 한다 (이 버전은 개념만).

 [v11 단계 1]  canary 로 시작
   canary = 실험용 파일에 일부러 심어 둔 고유한 문자열 (WSCANARY-config-1a2b ...).
   보통 문장은 여러 파일에 같이 있을 수 있지만, 무작위 토큰은 그 파일에만 있다.
   -> 요청 body 에서 그 토큰이 보이면 "그 파일에서 온 바이트" 라는 게 모호하지 않다.

     ./v11_provenance flows.jsonl ./sandbox
       1) sandbox 의 파일을 전부 읽어서 WSCANARY-... 토큰을 모은다 (토큰 -> 파일:줄)
       2) flows.jsonl (v1/v2 가 쓴 기록) 의 요청/응답 body 를 base64 에서 풀어서 토큰을 찾는다
       3) 본 것 / 한 번도 안 나온 것 / 어느 파일에도 없는데 트래픽에 있는 것 을 출력

 [v11 단계 2]  canary 가 없는 파일: "줄 run" 으로 찾기
   파일 내용은 보통 JSON 문자열 안에 escape 된 채로 나간다 ("a\nb" -> a, 줄바꿈, b).
   -> body 를 JSON 으로 파싱해서 문자열 값 하나하나를 '원래 글'로 되돌린 view 를 만들고 ($.messages[2].content 같은 경로와 함께),
      파일의 연속된 줄이 view 의 연속된 줄로 나오는 구간(run)을 찾는다.
   규칙 (본체 provenance.js 와 같음):
     - 줄은 앞뒤 공백을 빼고 비교 (들여쓰기·CRLF 차이 무시)
     - 짧거나 괄호뿐인 '사소한 줄'(}, return;)은 run 을 이어 줄 수만 있고 시작은 못 한다 — 어디에나 있으니 증거가 안 됨
     - 의미 있는 줄이 2개 이상 이어져야 일치로 인정
     - 파일 읽기 도구가 붙이는 줄번호("     1→code")는 view 의 60% 이상이 그 모양이면 떼고 비교
   본체에만 있는 것: gzip, SSE 이벤트 이어붙이기, base64 첨부, multipart, 바이너리 파일, 긴 줄 인용(fragment), 화면.

 ★ 증명하는 것과 못 하는 것
   증명: 이 토큰(= 그 파일의 바이트)이 이 요청 body 안에 있었다 (프록시가 캡처한 범위에서).
   못 함: 어느 프로세스가 그 파일을 읽었는지, 캡처 밖(QUIC, 프록시 무시)으로 나간 게 없는지.
============================================================
*/

#include "json.hpp"

#include <algorithm>
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

// ------------------------------------------------------------
// 단계 2: view 와 줄 run
// ------------------------------------------------------------
struct View {
    uint64_t flow;
    std::string side, where, how, text;   // where = "body" 또는 JSON 경로, how = 거친 변환
};

static void jsonStrings(const json& v, const std::string& path, std::vector<std::pair<std::string, std::string>>& out) {
    if (v.is_string()) { out.emplace_back(path, v.get<std::string>()); return; }
    if (v.is_array()) { for (size_t i = 0; i < v.size(); i++) jsonStrings(v[i], path + "[" + std::to_string(i) + "]", out); return; }
    if (v.is_object()) for (auto& [k, x] : v.items()) jsonStrings(x, path + "." + k, out);
}

static std::vector<View> makeViews(const std::vector<Body>& bodies) {
    std::vector<View> views;
    for (auto& b : bodies) {
        views.push_back({b.flow, b.side, "body", "as captured", b.bytes});
        json j = json::parse(b.bytes, nullptr, false);
        if (j.is_discarded()) continue;
        std::vector<std::pair<std::string, std::string>> strings;
        jsonStrings(j, "$", strings);
        for (auto& [path, value] : strings)
            if (value.size() >= 4) views.push_back({b.flow, b.side, path, "json", value});
    }
    return views;
}

static std::string trimmed(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r");
    if (a == std::string::npos) return "";
    return s.substr(a, s.find_last_not_of(" \t\r") - a + 1);
}
static std::vector<std::string> splitLines(const std::string& text) {
    std::vector<std::string> out;
    size_t start = 0;
    for (;;) {
        size_t nl = text.find('\n', start);
        out.push_back(text.substr(start, nl == std::string::npos ? std::string::npos : nl - start));
        if (nl == std::string::npos) return out;
        start = nl + 1;
    }
}
// 짧거나 괄호/기호뿐인 줄은 증거가 못 된다
static bool trivial(const std::string& line) {
    return line.size() < 8 || line.find_first_not_of(" {}()[];,.:'\"`<>/*#=-") == std::string::npos;
}
// "     1→code", "12\tcode", "  7: code", "3 | code" 같은 줄번호 접두어
static bool stripNumbers(std::vector<std::string>& lines) {
    static const std::regex prefix("^\\s*\\d+(→|\t| \\| |: )");
    size_t nonEmpty = 0, numbered = 0;
    for (auto& l : lines) if (!trimmed(l).empty()) { nonEmpty++; if (std::regex_search(l, prefix)) numbered++; }
    if (nonEmpty < 2 || numbered * 10 < nonEmpty * 6) return false;
    for (auto& l : lines) l = std::regex_replace(l, prefix, "", std::regex_constants::format_first_only);
    return true;
}

struct Run {
    int fileFrom, fileTo, viewFrom, viewTo, anchors;
};

// 파일 줄 i 와 view 줄 j 가 같으면 (i-1, j-1) 에서 끝난 run 을 이어 받는다 (대각선으로 늘리기)
static std::vector<Run> lineRuns(const std::vector<std::string>& fileLines, const std::vector<std::string>& viewLines) {
    std::map<std::string, std::vector<int>> index;
    for (int i = 0; i < int(fileLines.size()); i++) index[fileLines[i]].push_back(i);
    std::vector<Run> done;
    std::map<int, Run> prev;
    for (int j = 0; j < int(viewLines.size()); j++) {
        std::map<int, Run> cur;
        const std::string& line = viewLines[j];
        auto it = index.find(line);
        if (it != index.end()) {
            for (int i : it->second) {
                auto before = prev.find(i - 1);
                if (before == prev.end() && (line.empty() || trivial(line))) continue;   // 사소한 줄은 시작 못 함
                Run r = before != prev.end() ? before->second : Run{i, i, j, j, 0};
                if (!line.empty()) { r.fileTo = i; r.viewTo = j; }
                if (!line.empty() && !trivial(line)) r.anchors++;
                cur[i] = r;
            }
        }
        for (auto& [i, r] : prev) if (!cur.count(i + 1) && r.anchors >= 2) done.push_back(r);
        prev = std::move(cur);
    }
    for (auto& [i, r] : prev) if (r.anchors >= 2) done.push_back(r);
    return done;
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

    // 3) 단계 2: 줄 run
    printf("\nLINE RUNS (파일 줄 -> 요청 안의 위치)\n");
    auto views = makeViews(bodies);
    int found = 0;
    for (auto& f : files) {
        if (f.content.find('\0') != std::string::npos) continue;           // 바이너리 파일은 이 버전에선 건너뜀
        std::vector<std::string> fileLines = splitLines(f.content);
        for (auto& l : fileLines) l = trimmed(l);
        for (auto& v : views) {
            std::vector<std::string> viewLines = splitLines(v.text);
            bool numbered = stripNumbers(viewLines);
            for (auto& l : viewLines) l = trimmed(l);
            for (auto& r : lineRuns(fileLines, viewLines)) {
                found++;
                printf("  %-20s lines %d-%d  ->  #%llu %s  at %s  [%s%s]\n", f.name.c_str(), r.fileFrom + 1, r.fileTo + 1, (unsigned long long)v.flow,
                       v.side.c_str(), v.where.c_str(), v.how.c_str(), numbered ? ", line-numbers" : "");
            }
        }
    }
    if (!found) printf("  없음\n");
    return 0;
}
