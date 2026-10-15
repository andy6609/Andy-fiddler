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
#include <vector>

namespace ws {
using json = nlohmann::json;
using Headers = std::vector<std::pair<std::string, std::string>>;
constexpr size_t BODY_LIMIT = 1024 * 1024;
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
// UTF-8 string -> path without the C++20-deprecated u8path (matters for Windows profile paths).
inline std::filesystem::path utf8Path(const std::string& s) { return std::filesystem::path(std::u8string(s.begin(), s.end())); }
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
    uint64_t revision() const { return revision_.load(); }
private:
    void evict();
    mutable std::mutex mutex_;
    std::map<uint64_t, Flow> flows_;
    std::deque<Packet> packets_;
    json session_ = {{"name", "Untitled capture"}, {"client", ""}, {"action", ""}, {"notes", ""}, {"sample", false}};
    uint64_t nextFlow_ = 1, nextPacket_ = 1, droppedFlows_ = 0, droppedPackets_ = 0;
    size_t bodyBytes_ = 0, packetBytes_ = 0;
    std::atomic<uint64_t> revision_{1};
};
void sample(Store&);
std::string htmlReport(const json&, const std::string& css, const std::string& script, bool redact);
json redactedArchive(json);
}
