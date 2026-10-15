/*
============================================================
 v8_diff_report  —  두 요청을 '구조'로 비교하기
============================================================
 목적: 같은 작업("이 PDF 요약해줘")을 Claude Code / Codex / 브라우저로 각각 해 보면
       요청이 어떻게 다른가? 눈으로 JSON 두 개를 번갈아 보면 금방 놓친다.
       -> JSON 을 '잎(leaf) 경로' 단위로 펼쳐서 추가/삭제/변경을 기계적으로 뽑는다.
       (claude-tap 의 prompt diff 아이디어. WireScope 본체 Compare 화면의 원형)

   {"model":"m","messages":[{"role":"user","content":"hi"}]}
     ->  $.model                    = "m"
         $.messages[0].role         = "user"
         $.messages[0].content      = "hi"

   두 요청의 경로 집합을 비교:
     A 에만 있음 -> removed,  B 에만 있음 -> added,  둘 다 있는데 값 다름 -> changed

 ★ 원칙: "B 가 파일을 더 많이 보냈다" 같은 '판단'은 출력하지 않는다.
         어느 경로가 어떻게 달라졌는지, 몇 개인지만. 해석은 사람이.
 ★ 정규화는 숨기지 않는다: --ignore 로 뺀 경로는 출력에 "ignored by ..." 로 꼭 표시.
   (user_id, 타임스탬프처럼 매번 다른 값 때문에 진짜 차이가 묻히는 걸 막으려고 빼는 거지, 몰래 빼는 게 아님)

 [v8 단계 1 — 이 커밋]
     ./v8_diff_report flows.jsonl                       기록 목록 (번호 = 줄 번호, v7 의 _id 와 같음)
     ./v8_diff_report flows.jsonl 3 5                   3번 vs 5번 요청 body
     ./v8_diff_report flows.jsonl 3 5 --part resHeaders --ignore "date,x-request-id"
       --part : reqBody(기본) | resBody | reqHeaders | resHeaders
       --ignore: 쉼표 구분, [*] = 아무 인덱스, * = 아무 키 한 칸.  예) messages[*].content
       --same  : 같은 경로도 출력
============================================================
*/

#include "json.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

// ordered_json: 키 순서를 원본 그대로 유지 (기본 json 은 알파벳순으로 정렬해 버린다).
// 클라이언트가 필드를 어떤 순서로 보내는지도 관찰 대상이라서.
using json = nlohmann::ordered_json;


// ------------------------------------------------------------
// base64 디코드 (v1~v3 이 body 를 base64 로 기록했으니까)
// ------------------------------------------------------------
static std::string unbase64(const std::string& in) {
    static int T[256];
    static bool init = false;
    if (!init) {
        std::fill(std::begin(T), std::end(T), -1);
        const char* a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; i++) T[uint8_t(a[i])] = i;
        init = true;
    }
    std::string out;
    uint32_t buf = 0;
    int bits = 0;
    for (unsigned char c : in) {
        if (T[c] < 0) continue;                 // '=' 패딩, 줄바꿈 무시
        buf = (buf << 6) | uint32_t(T[c]);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += char((buf >> bits) & 0xff);
        }
    }
    return out;
}


// ------------------------------------------------------------
// JSON -> 잎 경로 목록 (순서 유지)
// ------------------------------------------------------------
static std::string keyPath(const std::string& k) {
    bool plain = !k.empty() && (std::isalpha(uint8_t(k[0])) || k[0] == '_' || k[0] == '$');
    for (char c : k) plain = plain && (std::isalnum(uint8_t(c)) || c == '_' || c == '$' || c == '-');
    return plain ? "." + k : "[" + json(k).dump() + "]";      // 이상한 키는 ["a.b"] 처럼
}
static void flatten(const json& v, const std::string& path, std::vector<std::pair<std::string, std::string>>& out) {
    if (v.is_array()) {
        if (v.empty()) out.emplace_back(path, "[]");
        for (size_t i = 0; i < v.size(); i++) flatten(v[i], path + "[" + std::to_string(i) + "]", out);
    } else if (v.is_object()) {
        if (v.empty()) out.emplace_back(path, "{}");
        for (auto& [k, x] : v.items()) flatten(x, path + keyPath(k), out);
    } else {
        out.emplace_back(path, v.dump());       // 잎 값은 JSON 표기 그대로 ("m", 3, true, null)
    }
}


// ------------------------------------------------------------
// --ignore 패턴 -> 정규식
//   "messages[*].content" -> ^\$\.messages\[\d+\]\.content(?:$|[.\[])
//   끝의 (?:$|[.\[]) : 접두어 일치 — 그 경로 '아래' 전부도 같이 무시
// ------------------------------------------------------------
struct IgnoreRule {
    std::string label;
    std::regex re;
};
static std::vector<IgnoreRule> parseIgnore(const std::string& text) {
    std::vector<IgnoreRule> rules;
    std::stringstream ss(text);
    std::string item;
    while (std::getline(ss, item, ',')) {
        item.erase(0, item.find_first_not_of(' '));
        item.erase(item.find_last_not_of(' ') + 1);
        if (item.empty()) continue;
        std::string p = item[0] == '$' ? item : item[0] == '[' ? "$" + item : "$." + item;
        std::string re;
        for (size_t i = 0; i < p.size(); i++) {
            if (p.compare(i, 3, "[*]") == 0) { re += "\\[\\d+\\]"; i += 2; }
            else if (p[i] == '*') re += "[^.\\[]*";
            else if (std::string(".[]()$^+?{}|\\").find(p[i]) != std::string::npos) { re += '\\'; re += p[i]; }
            else re += p[i];
        }
        rules.push_back({item, std::regex("^" + re + "(?:$|[.\\[])")});
    }
    return rules;
}


// ------------------------------------------------------------
// 비교할 부분 꺼내기
// ------------------------------------------------------------
struct Side {
    bool isJson = false;
    json value;
    std::string bytes, note;
};

static json headersObject(const json& headers) {
    json o = json::object();
    if (!headers.is_array()) return o;
    for (auto& h : headers) {
        if (!h.is_array() || h.size() != 2) continue;
        std::string k = h[0].get<std::string>();
        std::transform(k.begin(), k.end(), k.begin(), [](unsigned char c) { return char(std::tolower(c)); });   // 헤더 이름은 대소문자 무관
        if (!o.contains(k)) o[k] = h[1];
        else {
            if (!o[k].is_array()) o[k] = json::array({o[k]});
            o[k].push_back(h[1]);                         // 같은 이름이 여러 번이면 배열로
        }
    }
    return o;
}

static Side extract(const json& rec, const std::string& part) {
    Side s;
    if (part == "reqHeaders" || part == "resHeaders") {
        s.isJson = true;
        s.value = headersObject(rec.value(part == "reqHeaders" ? "requestHeaders" : "responseHeaders", json::array()));
        return s;
    }
    const json& body = rec.value(part == "resBody" ? "response" : "request", json::object());
    s.bytes = unbase64(body.value("base64", ""));
    if (body.value("truncated", false)) s.note = "body truncated at capture (" + std::to_string(body.value("captured", 0)) + " of " + std::to_string(body.value("total", 0)) + " bytes)";
    try {
        s.value = json::parse(s.bytes);
        s.isJson = true;
    } catch (...) {
    }
    return s;
}

static std::string describe(const json& r, size_t index) {
    std::string m = r.value("method", r.value("kind", std::string("?")));
    std::string host = r.value("host", std::string(""));
    std::string path = r.value("path", std::string(""));
    return "#" + std::to_string(index) + " " + m + " " + host + path;
}


// ------------------------------------------------------------
// 비교 결과
// ------------------------------------------------------------
struct Row {
    std::string kind, path, a, b;
};
struct Diff {
    std::vector<Row> rows;
    std::map<std::string, int> counts;
    std::vector<std::string> notes;
};

static Diff compare(const Side& A, const Side& B, const std::vector<IgnoreRule>& rules, bool showSame) {
    Diff d;
    for (auto k : {"added", "removed", "changed", "same", "ignored"}) d.counts[k] = 0;
    if (!A.isJson || !B.isJson) {
        // JSON 이 아니면 구조 비교는 못 한다. 관측 가능한 사실만: 크기, 첫 번째로 다른 바이트 위치
        size_t n = std::min(A.bytes.size(), B.bytes.size()), i = 0;
        while (i < n && A.bytes[i] == B.bytes[i]) i++;
        d.notes.push_back("not JSON on both sides: A " + std::to_string(A.bytes.size()) + " bytes, B " + std::to_string(B.bytes.size()) + " bytes, " +
                          (A.bytes == B.bytes ? "identical" : "first difference at byte " + std::to_string(i)));
        return d;
    }
    std::vector<std::pair<std::string, std::string>> fa, fb;
    flatten(A.value, "$", fa);
    flatten(B.value, "$", fb);
    std::map<std::string, std::string> ma(fa.begin(), fa.end()), mb(fb.begin(), fb.end());
    std::vector<std::string> order;
    for (auto& [p, v] : fa) order.push_back(p);
    for (auto& [p, v] : fb) if (!ma.count(p)) order.push_back(p);
    for (auto& p : order) {
        if (std::any_of(rules.begin(), rules.end(), [&](const IgnoreRule& r) { return std::regex_search(p, r.re); })) {
            d.counts["ignored"]++;
            continue;
        }
        auto ia = ma.find(p), ib = mb.find(p);
        std::string kind = ia == ma.end() ? "added" : ib == mb.end() ? "removed" : ia->second == ib->second ? "same" : "changed";
        d.counts[kind]++;
        if (kind != "same" || showSame) d.rows.push_back({kind, p, ia == ma.end() ? "" : ia->second, ib == mb.end() ? "" : ib->second});
    }
    return d;
}

static std::string cut(const std::string& s, size_t n) { return s.size() > n ? s.substr(0, n) + "…" : s; }

static void printDiff(const Diff& d, const std::vector<IgnoreRule>& rules) {
    for (auto& n : d.notes) printf("  note: %s\n", n.c_str());
    if (d.rows.empty() && d.notes.empty() && !d.counts.at("added") && !d.counts.at("removed") && !d.counts.at("changed")) printf("  차이 없음\n");
    printf("  %d added · %d removed · %d changed · %d unchanged", d.counts.at("added"), d.counts.at("removed"), d.counts.at("changed"), d.counts.at("same"));
    if (d.counts.at("ignored")) {
        printf(" · %d ignored by:", d.counts.at("ignored"));
        for (auto& r : rules) printf(" %s", r.label.c_str());
    }
    printf("   (leaf paths, A -> B, arrays by index)\n\n");
    for (auto& r : d.rows) printf("  %-8s %-44s %-30s %s\n", r.kind.c_str(), cut(r.path, 44).c_str(), cut(r.a, 30).c_str(), cut(r.b, 60).c_str());
}


static std::vector<json> readJsonl(const std::string& path) {
    std::ifstream in(path);
    std::vector<json> out;
    std::string line;
    while (std::getline(in, line))
        if (!line.empty()) out.push_back(json::parse(line, nullptr, false));   // 깨진 줄은 discarded 로 남겨 번호 유지
    return out;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("사용법: %s flows.jsonl [A B] [--part reqBody|resBody|reqHeaders|resHeaders] [--ignore p1,p2] [--same]\n", argv[0]);
        return 1;
    }
    std::vector<size_t> ids;
    std::string part = "reqBody", ignore;
    bool same = false;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--part" && i + 1 < argc) part = argv[++i];
        else if (a == "--ignore" && i + 1 < argc) ignore = argv[++i];
        else if (a == "--same") same = true;
        else ids.push_back(std::strtoul(a.c_str(), nullptr, 10));
    }
    auto records = readJsonl(argv[1]);
    if (ids.size() < 2) {
        for (size_t i = 0; i < records.size(); i++)
            if (!records[i].is_discarded()) printf("%s\n", describe(records[i], i + 1).c_str());
        return 0;
    }
    for (size_t id : {ids[0], ids[1]})
        if (!id || id > records.size() || records[id - 1].is_discarded()) {
            printf("기록 %zu 없음\n", id);
            return 1;
        }
    const json &A = records[ids[0] - 1], &B = records[ids[1] - 1];
    auto rules = parseIgnore(ignore);
    printf("A = %s\nB = %s\npart = %s\n\n", describe(A, ids[0]).c_str(), describe(B, ids[1]).c_str(), part.c_str());
    Side sa = extract(A, part), sb = extract(B, part);
    if (!sa.note.empty()) printf("  A: %s\n", sa.note.c_str());
    if (!sb.note.empty()) printf("  B: %s\n", sb.note.c_str());
    printDiff(compare(sa, sb, rules, same), rules);
    return 0;
}
