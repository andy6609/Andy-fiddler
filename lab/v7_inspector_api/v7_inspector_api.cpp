/*
============================================================
 v7_inspector_api  —  엔진(C++)과 화면(브라우저)을 나누기
============================================================
 목적: v1~v6 은 결과를 콘솔과 파일로만 냈다. 계속 쌓이는 기록을 사람이 탐색하려면 화면이 필요하다.
       WireScope 는 Qt 같은 네이티브 창 대신 "C++ 엔진 + 로컬 HTTP API + 브라우저 UI" 를 택했다.
         - 같은 HTML/JS 화면을 나중에 '독립 HTML 보고서'로도 재사용할 수 있고 (v8)
         - 엔진은 데이터만, 화면은 표현만 맡아서 각각 바꾸기 쉽다.
       v7 은 그 구조의 뼈대만 따로 떼어 만든 것.

 [v7 단계 1]  Store + 파일 따라가기 + 조회 API
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

 [v7 단계 2]  보안 경계 + 브라우저 화면
   "127.0.0.1 에서만 열었으니 안전하다" 는 착각이다.
   내 브라우저에 열려 있는 '아무 웹사이트'의 JS 도 http://127.0.0.1:18087 로 요청을 보낼 수 있다.
   이 API 는 캡처한 토큰/쿠키/파일 내용을 들고 있으니 막아야 한다:

     1) Host 검사  — DNS rebinding 방어.
        evil.com 의 DNS 를 잠깐 127.0.0.1 로 바꾸면 브라우저는 evil.com 페이지에서 '같은 출처'로
        내 API 를 읽을 수 있게 된다. 이때 Host 헤더는 evil.com:18087 로 온다 -> 거절.
     2) 토큰      — /api/bootstrap 이 실행마다 새로 만든 토큰을 주고, 나머지 /api/... 요청은 헤더에 토큰 필수.
        다른 출처의 JS 는 CORS 때문에 bootstrap 응답을 '읽을' 수 없다 -> 토큰을 모른다.
     3) Origin 검사 — Origin 헤더가 있는데 우리 주소가 아니면 거절 (CSRF: 남의 페이지가 대신 보내는 요청).
     4) CSP       — 우리 페이지에서는 우리 서버의 스크립트만 실행. 캡처된 body 를 화면에 넣을 때는
                     innerHTML 이 아니라 textContent 로 (캡처한 HTML 이 실행되면 안 되니까).
   WireScope 본체 main.cpp 가 같은 네 가지를 한다. 테스트로 각각 403 이 나는지 확인.
============================================================
*/

#include "httplib.h"   // cpp-httplib (third_party): 헤더 하나짜리 HTTP 서버/클라이언트
#include "json.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <random>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using json = nlohmann::json;

static const int UI_PORT = 18087;

// 실행마다 새로 만드는 토큰 (32 hex). 진짜 서비스라면 OS CSPRNG 를 직접 쓰는 게 맞고,
// std::random_device 도 대부분 플랫폼에서 OS 난수를 쓴다.
static std::string newToken() {
    std::random_device rd;
    std::string t;
    const char* hex = "0123456789abcdef";
    for (int i = 0; i < 32; i++) t += hex[rd() % 16];
    return t;
}

// ---- 화면 (HTML + JS) — 파일 하나로 배포하려고 문자열로 박아 둠 ----
static const char* PAGE = R"HTML(<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><title>WireScope lab v7</title>
<style>
 body{font:13px system-ui,sans-serif;margin:0;display:grid;grid-template-columns:1fr 1fr;height:100vh}
 #list{overflow:auto;border-right:1px solid #ccd}#detail{overflow:auto;padding:10px}
 table{border-collapse:collapse;width:100%}td,th{padding:5px 8px;border-bottom:1px solid #eef;text-align:left;font-family:monospace;font-size:12px}
 tr:hover{background:#f0f5fb;cursor:pointer}pre{white-space:pre-wrap;word-break:break-all;font-size:12px}
 header{padding:8px;background:#182d40;color:#fff;grid-column:1/3}
</style></head><body>
<header>WireScope lab v7 — <span id="status">connecting…</span></header>
<div id="list"><table><thead><tr><th>#</th><th>method</th><th>host</th><th>path</th><th>status</th><th>req</th><th>res</th></tr></thead><tbody id="rows"></tbody></table></div>
<div id="detail">왼쪽에서 한 건을 고르면 전체 기록이 여기 나옵니다.</div>
<script src="/app.js"></script></body></html>)HTML";

static const char* SCRIPT = R"JS(
// 화면 쪽: 토큰 받기 -> 1초마다 revision 으로 변경 확인 -> 표 다시 그리기
let token = '', revision = 0;
const api = (path) => fetch(path, { headers: { 'X-Lab-Token': token } }).then(r => r.json());
function cell(text) { const td = document.createElement('td'); td.textContent = text ?? ''; return td; }   // textContent: 캡처 내용이 HTML 로 실행되지 않게
function render(records) {
  const body = document.getElementById('rows');
  body.replaceChildren();
  for (const r of records) {
    const tr = document.createElement('tr');
    const status = r.status ?? r.state ?? '';
    for (const v of [r._id, r.method ?? r.kind, r.host, r.path ?? ('stream ' + (r.stream ?? '')), status, r.request?.total, r.response?.total]) tr.append(cell(v));
    tr.onclick = () => api('/api/flows/' + r._id).then(show);
    body.append(tr);
  }
}
function decode(b64) {
  try { const t = new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(b64), c => c.charCodeAt(0))); return t; }
  catch { return '(binary ' + atob(b64).length + ' bytes)'; }
}
function show(r) {
  const out = document.getElementById('detail');
  out.replaceChildren();
  for (const side of ['request', 'response']) if (r[side]?.base64) {
    const h = document.createElement('h4'); h.textContent = side + ' body (' + r[side].captured + ' of ' + r[side].total + ' bytes)';
    const pre = document.createElement('pre'); pre.textContent = decode(r[side].base64);
    out.append(h, pre);
  }
  const pre = document.createElement('pre'); pre.textContent = JSON.stringify(r, null, 2); out.append(pre);
}
async function poll() {
  try {
    const s = await api('/api/state?revision=' + revision);
    if (!s.unchanged) { revision = s.revision; render(s.records); }
    document.getElementById('status').textContent = 'revision ' + revision;
  } catch (e) { document.getElementById('status').textContent = 'engine unreachable'; }
  setTimeout(poll, 1000);
}
fetch('/api/bootstrap').then(r => r.json()).then(b => { token = b.token; poll(); });
)JS";


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
#ifdef _WIN32
    setvbuf(stdout, nullptr, _IONBF, 0);   // MSVC: _IOLBF 없음 + 크기 0 이면 즉시 종료 (lab_net.hpp 의 lineBufferedStdout 참고)
#else
    setvbuf(stdout, nullptr, _IOLBF, 0);
#endif
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
    const std::string token = newToken();
    const std::string self = "127.0.0.1:" + std::to_string(UI_PORT), selfName = "localhost:" + std::to_string(UI_PORT);

    // 모든 요청이 라우팅 전에 여기를 지난다 = 보안 검사 한 곳에 모으기
    server.set_pre_routing_handler([&](const httplib::Request& req, httplib::Response& res) {
        std::string host = req.get_header_value("Host");
        if (host != self && host != selfName) {                                   // 1) DNS rebinding
            res.status = 403;
            sendJson(res, {{"error", "Host not allowed"}});
            return httplib::Server::HandlerResponse::Handled;
        }
        std::string origin = req.get_header_value("Origin");
        if (!origin.empty() && origin != "http://" + self && origin != "http://" + selfName) {   // 3) CSRF
            res.status = 403;
            sendJson(res, {{"error", "cross-origin request blocked"}});
            return httplib::Server::HandlerResponse::Handled;
        }
        if (req.path.rfind("/api/", 0) == 0 && req.path != "/api/bootstrap" && req.get_header_value("X-Lab-Token") != token) {   // 2) token
            res.status = 403;
            sendJson(res, {{"error", "token required"}});
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });
    server.set_post_routing_handler([](const httplib::Request&, httplib::Response& res) {
        res.set_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'");   // 4) CSP
        res.set_header("X-Content-Type-Options", "nosniff");
        res.set_header("Cache-Control", "no-store");
    });
    server.Get("/", [](const httplib::Request&, httplib::Response& res) { res.set_content(PAGE, "text/html; charset=utf-8"); });
    server.Get("/app.js", [](const httplib::Request&, httplib::Response& res) { res.set_content(SCRIPT, "text/javascript; charset=utf-8"); });
    server.Get("/favicon.ico", [](const httplib::Request&, httplib::Response& res) { res.status = 204; });   // 브라우저가 자동으로 찾는 아이콘: 없음
    server.Get("/api/bootstrap", [&](const httplib::Request&, httplib::Response& res) { sendJson(res, {{"token", token}}); });
    server.Get("/api/state", [&](const httplib::Request& req, httplib::Response& res) {
        uint64_t rev = req.has_param("revision") ? std::stoull(req.get_param_value("revision")) : UINT64_MAX;
        sendJson(res, store.state(rev));
    });
    server.Get(R"(/api/flows/(\d+))", [&](const httplib::Request& req, httplib::Response& res) {
        json r = store.get(std::stoul(req.matches[1].str()));
        if (r.is_null()) res.status = 404;
        sendJson(res, r);
    });

    printf("[v7] %s 따라가는 중 -> 브라우저에서 http://127.0.0.1:%d/\n", argv[1], UI_PORT);
    server.listen("127.0.0.1", UI_PORT);          // 127.0.0.1 에만: 같은 네트워크의 다른 PC 는 접근 불가
    running = false;
    follower.join();
    return 0;
}
