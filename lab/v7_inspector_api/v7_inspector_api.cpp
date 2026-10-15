/*
============================================================
 v7_inspector_api  —  엔진(C++)과 화면(브라우저)을 나누기
============================================================
 목적: v1~v6 은 결과를 콘솔과 파일로만 냈다. 계속 쌓이는 기록을 사람이 탐색하려면 화면이 필요하다.
       WireScope 는 Qt 같은 네이티브 창 대신 "C++ 엔진 + 로컬 HTTP API + 브라우저 UI" 를 택했다.
         - 같은 HTML/JS 화면을 나중에 '독립 HTML 보고서'로도 재사용할 수 있고 (v8)
         - 엔진은 데이터만, 화면은 표현만 맡아서 각각 바꾸기 쉽다.
       v7 은 그 구조의 뼈대만 따로 떼어 만든 것.

 [v7 단계 1 — 이 커밋]  Store + 파일 따라가기 + 조회 API
     ./v7_inspector_api flows.jsonl          (v1/v2/v3 가 쓰고 있는 파일을 그대로 지정)
       GET /api/state?revision=N     -> 바뀐 게 없으면 {"unchanged":true}, 있으면 요약 목록
       GET /api/flows/{id}           -> 한 건 전체 (body base64 포함)

   ★ revision(변경 번호) 을 쓰는 이유:
     화면은 1초마다 "뭐 바뀐 거 있어?" 하고 묻는다(polling).
     매번 전체 목록(수천 건)을 보내면 낭비라서, 엔진은 데이터가 바뀔 때마다 revision 을 +1 하고
     화면은 마지막으로 받은 revision 을 같이 보낸다 -> 같으면 몇 바이트짜리 "unchanged" 만 돌려줌.
     (WireScope 본체 /api/state 가 같은 방식)

   ★ 목록에는 '요약'만:
     body(base64)는 클 수 있으니 목록에선 빼고, 사용자가 한 건을 클릭했을 때만 /api/flows/{id} 로 가져온다.
============================================================
*/

#include "httplib.h"   // cpp-httplib (third_party): 헤더 하나짜리 HTTP 서버/클라이언트
#include "json.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using json = nlohmann::json;

static const int UI_PORT = 18087;


// ------------------------------------------------------------
// Store: 기록을 메모리에 들고 있고, 바뀔 때마다 revision++
// ------------------------------------------------------------
class Store {
public:
    void add(json record) {
        std::lock_guard<std::mutex> lock(m_);
        record["_id"] = records_.size() + 1;              // 화면용 번호 (v1/v2 id, v3 stream 등 원본 id 와 별개)
        records_.push_back(std::move(record));
        ++revision_;
    }
    uint64_t revision() const { return revision_.load(); }

    json state(uint64_t clientRevision) const {
        std::lock_guard<std::mutex> lock(m_);
        if (clientRevision == revision_) return {{"unchanged", true}, {"revision", revision_.load()}};
        json list = json::array();
        for (auto& r : records_) list.push_back(summary(r));
        return {{"revision", revision_.load()}, {"records", list}};
    }
    json get(size_t id) const {
        std::lock_guard<std::mutex> lock(m_);
        if (id == 0 || id > records_.size()) return nullptr;
        return records_[id - 1];
    }

private:
    // 목록용 요약: body 의 base64 는 빼고 크기 정보만 남긴다
    static json summary(json r) {
        for (auto side : {"request", "response"})
            if (r.contains(side) && r[side].is_object()) r[side].erase("base64");
        r.erase("frames");                                  // v3 h2-connection 의 프레임 목록도 상세에서만
        return r;
    }
    mutable std::mutex m_;
    std::vector<json> records_;
    std::atomic<uint64_t> revision_{0};
};


// ------------------------------------------------------------
// 파일 따라가기 (tail -f 처럼)
//   다른 프로세스(v1~v3)가 한 줄씩 append 하는 파일을 300ms 마다 확인해서
//   '줄바꿈까지 완성된' 새 줄만 읽는다. 쓰는 도중인 반쪽 줄은 다음 번에.
// ------------------------------------------------------------
static void follow(const std::string& path, Store& store, std::atomic<bool>& running) {
    std::streamoff offset = 0;
    std::string partial;
    while (running) {
        std::ifstream in(path, std::ios::binary);
        if (in) {
            in.seekg(0, std::ios::end);
            std::streamoff size = in.tellg();
            if (size < offset) { offset = 0; partial.clear(); }   // 파일이 새로 만들어졌으면 처음부터
            if (size > offset) {
                in.seekg(offset);
                std::string chunk(size_t(size - offset), '\0');
                in.read(chunk.data(), std::streamsize(chunk.size()));
                offset = size;
                partial += chunk;
                size_t nl;
                while ((nl = partial.find('\n')) != std::string::npos) {
                    std::string line = partial.substr(0, nl);
                    partial.erase(0, nl + 1);
                    if (line.empty()) continue;
                    try {
                        store.add(json::parse(line));
                    } catch (const std::exception& e) {
                        printf("[v7] JSON 아닌 줄 건너뜀: %s\n", e.what());
                    }
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
}


int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    if (argc < 2) {
        printf("사용법: %s flows.jsonl   (v1/v2/v3 가 기록하는 파일)\n", argv[0]);
        return 1;
    }
    Store store;
    std::atomic<bool> running{true};
    std::thread follower(follow, std::string(argv[1]), std::ref(store), std::ref(running));

    httplib::Server server;
    auto sendJson = [](httplib::Response& res, const json& j) {
        res.set_content(j.dump(-1, ' ', false, json::error_handler_t::replace), "application/json; charset=utf-8");
    };
    server.Get("/api/state", [&](const httplib::Request& req, httplib::Response& res) {
        uint64_t rev = req.has_param("revision") ? std::stoull(req.get_param_value("revision")) : UINT64_MAX;
        sendJson(res, store.state(rev));
    });
    server.Get(R"(/api/flows/(\d+))", [&](const httplib::Request& req, httplib::Response& res) {
        json r = store.get(std::stoul(req.matches[1].str()));
        if (r.is_null()) res.status = 404;
        sendJson(res, r);
    });

    printf("[v7] %s 따라가는 중 -> http://127.0.0.1:%d/api/state\n", argv[1], UI_PORT);
    server.listen("127.0.0.1", UI_PORT);          // 127.0.0.1 에만: 같은 네트워크의 다른 PC 는 접근 불가
    running = false;
    follower.join();
    return 0;
}
