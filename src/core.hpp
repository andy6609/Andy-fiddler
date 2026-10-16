#pragma once
#include "json.hpp"
#include <atomic>
#include <chrono>
#include <deque>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace ws {
using json = nlohmann::json;
using Headers = std::vector<std::pair<std::string, std::string>>;
// Per-direction body capture limit. 1 MiB by default; experiments can raise it with --body-limit.
constexpr size_t DEFAULT_BODY_LIMIT = 1024 * 1024;
constexpr size_t MAX_BODY_LIMIT = 32 * 1024 * 1024;
// The TCP stream preview has its own fixed window, independent of the body limit.
constexpr size_t STREAM_PREVIEW_LIMIT = 1024 * 1024;
size_t bodyLimit();
void setBodyLimit(size_t bytes);
constexpr size_t MEMORY_LIMIT = 128 * 1024 * 1024;
int64_t nowMs();
std::string lower(std::string s);
std::string trim(std::string s);
std::string header(const Headers&, const std::string&);
std::string base64(const std::string&);
std::string unbase64(const std::string&);
std::string sha256(const std::string&);
std::string randomHex(size_t n = 16);
std::string safeJson(const json&);
std::string connectionKey(std::string a, std::string b);
std::string endpoint(const std::string& address, uint16_t port);
// UTF-8 string -> path. Plain path(std::string) would use the ANSI code page on Windows and mangle Korean profile paths.
inline std::filesystem::path utf8Path(const std::string& s) { return std::filesystem::u8path(s); }
// C++17 std::string has no starts_with/ends_with.
inline bool startsWith(std::string_view s, std::string_view prefix) { return s.substr(0, prefix.size()) == prefix; }
inline bool endsWith(std::string_view s, std::string_view suffix) { return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix; }
struct Body {
    std::string bytes;
    uint64_t total = 0;
    void append(const char*, size_t);
    json serialize() const;
};
struct Flow {
    json meta;
    Headers requestHeaders, responseHeaders;
    Body request, response;
    json timeline = json::array();
    json messages = json::array();
    std::string notes;
    json summary() const;
    json detail() const;
};
struct Packet {
    uint64_t id = 0;
    int64_t time = 0;
    int linkType = 1;
    uint32_t originalLength = 0;
    std::string device;
    std::string raw;
    json info;
    json summary() const;
    json detail() const;
};
// A local file snapshot registered for provenance matching ("which part of this file showed up in which request").
// Only the bytes the user hands over are stored; the engine never reads paths from disk on its own.
struct LocalFile {
    uint64_t id = 0;
    std::string name;      // label shown in the UI (usually a path relative to the experiment repo)
    std::string content;   // snapshot bytes at registration time
    std::string origin;    // "browser" (file picker) or "api" (experiment scripts)
    std::string hash;      // sha256 of content, computed once at registration
    int64_t added = 0;
    json summary() const;  // without content
    json detail() const;   // with base64 content
};
constexpr size_t LOCAL_FILE_LIMIT = 2 * 1024 * 1024;   // per file
constexpr size_t LOCAL_FILES_TOTAL = 32 * 1024 * 1024;  // all snapshots together
constexpr size_t LOCAL_FILES_MAX = 256;
class Store {
public:
    uint64_t createFlow(json meta, Headers headers = {});
    void edit(uint64_t, const std::function<void(Flow&)>&);
    json flow(uint64_t) const;
    void addPacket(Packet);
    json packet(uint64_t) const;
    json snapshot() const;
    json archive() const;
    void restore(const json&);
    void clear(const std::string& name, bool sample = false);
    void setSession(const json&);
    void note(uint64_t, const std::string&);
    std::vector<Packet> packets() const;
    uint64_t addLocalFile(const std::string& name, std::string content, const std::string& origin);
    bool removeLocalFile(uint64_t id);
    json localFile(uint64_t id) const;
    uint64_t revision() const { return revision_.load(); }
private:
    void evict();
    json localFileList(bool withContent) const;  // caller holds mutex_
    mutable std::mutex mutex_;
    std::map<uint64_t, Flow> flows_;
    std::deque<Packet> packets_;
    std::map<uint64_t, LocalFile> files_;
    uint64_t nextFile_ = 1;
    size_t fileBytes_ = 0;
    json session_ = {{"name", "Untitled capture"}, {"client", ""}, {"action", ""}, {"notes", ""}, {"sample", false}};
    uint64_t nextFlow_ = 1, nextPacket_ = 1, droppedFlows_ = 0, droppedPackets_ = 0;
    size_t bodyBytes_ = 0, packetBytes_ = 0;
    std::atomic<uint64_t> revision_{1};
};
void sample(Store&);
std::string htmlReport(const json&, const std::string& css, const std::string& script, bool redact);
json redactedArchive(json);
}
