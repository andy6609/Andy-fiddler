// Unit tests for the parts that do not need sockets: encoding, packet decoding,
// capture file I/O, TCP preview, session archive/restore and HTML export.
#include "core.hpp"
#include "packet.hpp"
#include <cstdio>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>

using namespace ws;
using namespace std::string_literals;

namespace {
int failures = 0, checks = 0;
#define CHECK(cond) do { ++checks; if (!(cond)) { ++failures; std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK failed: " #cond "\n"; } } while (0)
#define CHECK_EQ(a, b) do { ++checks; auto _a = (a); auto _b = (b); if (!(_a == _b)) { ++failures; std::cerr << __FILE__ << ":" << __LINE__ << ": " #a " == " #b " failed\n  left:  " << _a << "\n  right: " << _b << "\n"; } } while (0)
bool throws(const std::function<void()>& fn) { try { fn(); } catch (const std::exception&) { return true; } return false; }

void put16(std::string& s, size_t at, uint16_t v) { s[at] = char(v >> 8); s[at + 1] = char(v); }
void put32(std::string& s, size_t at, uint32_t v) { put16(s, at, uint16_t(v >> 16)); put16(s, at + 2, uint16_t(v)); }
void le32(std::string& s, uint32_t v) { for (int i = 0; i < 4; ++i) s.push_back(char(v >> (i * 8))); }
void le16(std::string& s, uint16_t v) { s.push_back(char(v)); s.push_back(char(v >> 8)); }

// Ethernet + IPv4 (10.0.0.1 -> 93.184.216.34) around a transport segment.
std::string ipv4Frame(uint8_t proto, const std::string& transport) {
    std::string eth(12, '\x11'); eth += "\x08\x00"s;
    std::string ip(20, '\0'); ip[0] = 0x45; put16(ip, 2, uint16_t(20 + transport.size())); ip[8] = 64; ip[9] = char(proto);
    ip[12] = 10; ip[13] = 0; ip[14] = 0; ip[15] = 1;
    ip[16] = char(93); ip[17] = char(184); ip[18] = char(216); ip[19] = char(34);
    return eth + ip + transport;
}
std::string tcp(uint16_t sp, uint16_t dp, uint32_t seq, uint8_t flags, const std::string& payload) {
    std::string t(20, '\0'); put16(t, 0, sp); put16(t, 2, dp); put32(t, 4, seq); t[12] = 0x50; t[13] = char(flags); return t + payload;
}
std::string udp(uint16_t sp, uint16_t dp, const std::string& payload) {
    std::string u(8, '\0'); put16(u, 0, sp); put16(u, 2, dp); put16(u, 4, uint16_t(8 + payload.size())); return u + payload;
}
std::string dnsQuery() {
    std::string d = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"s;
    d += "\x07" "example" "\x03" "com" "\x00"s; d += "\x00\x01\x00\x01"s; return d;
}

void encoding() {
    std::string all; for (int i = 0; i < 256; ++i) all.push_back(char(i));
    for (size_t n = 0; n <= all.size(); n += (n < 8 ? 1 : 37)) CHECK_EQ(unbase64(base64(all.substr(0, n))), all.substr(0, n));
    CHECK(throws([] { unbase64("abc"); }));
    CHECK(throws([] { unbase64("ab!="); }));
    CHECK_EQ(sha256("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"s);
    CHECK_EQ(endpoint("::1", 443), "[::1]:443"s);
    CHECK_EQ(connectionKey("b:1", "a:2"), connectionKey("a:2", "b:1"));
}

void bodyLimit() {
    Body b; std::string chunk(BODY_LIMIT / 2 + 1, 'x');
    b.append(chunk.data(), chunk.size()); b.append(chunk.data(), chunk.size()); b.append(chunk.data(), chunk.size());
    auto j = b.serialize();
    CHECK_EQ(j["captured"].get<size_t>(), BODY_LIMIT);
    CHECK_EQ(j["total"].get<uint64_t>(), uint64_t(chunk.size() * 3));
    CHECK(j["truncated"].get<bool>());
    CHECK_EQ(j["sha256"].get<std::string>(), ""s); // never claim a whole-body hash over a prefix
    Body small; small.append("abc", 3);
    CHECK_EQ(small.serialize()["sha256"].get<std::string>(), sha256("abc"));
}

void packets() {
    auto raw = ipv4Frame(6, tcp(51000, 80, 1000, 0x18, "GET / HTTP/1.1\r\nHost: example\r\n\r\n"));
    auto p = decodePacket(raw, 1, 1234, uint32_t(raw.size()), "test");
    CHECK_EQ(p.info["protocol"].get<std::string>(), "HTTP"s);
    CHECK_EQ(p.info["srcPort"].get<int>(), 51000);
    CHECK_EQ(p.info["dstPort"].get<int>(), 80);
    CHECK_EQ(p.info["source"].get<std::string>(), "10.0.0.1:51000"s);
    CHECK_EQ(p.info["payloadOffset"].get<size_t>(), size_t(54));
    CHECK(p.info["summary"].get<std::string>().starts_with("GET / HTTP/1.1"));
    CHECK(!p.info.contains("error"));
    // Every reported field must point at the bytes it describes.
    bool sawSource = false;
    for (auto& f : p.info["fields"]) {
        CHECK(f["offset"].get<size_t>() + f["length"].get<size_t>() <= raw.size());
        if (f["name"] == "IPv4 source") { sawSource = true; CHECK_EQ(raw.substr(f["offset"].get<size_t>(), 4), "\x0a\x00\x00\x01"s); }
    }
    CHECK(sawSource);

    auto tls = ipv4Frame(6, tcp(51001, 443, 5, 0x18, "\x16\x03\x01\x00\x05hello"s));
    CHECK_EQ(decodePacket(tls, 1, 0, uint32_t(tls.size()), "").info["protocol"].get<std::string>(), "TLS"s);

    auto dns = ipv4Frame(17, udp(53000, 53, dnsQuery()));
    auto d = decodePacket(dns, 1, 0, uint32_t(dns.size()), "");
    CHECK_EQ(d.info["protocol"].get<std::string>(), "DNS"s);
    CHECK_EQ(d.info["dnsName"].get<std::string>(), "example.com"s);

    // Compression pointer that points at itself: must be reported, not loop or crash.
    auto loop = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01"s;
    auto bad = ipv4Frame(17, udp(53000, 53, loop));
    CHECK(decodePacket(bad, 1, 0, uint32_t(bad.size()), "").info.contains("error"));

    // Truncated frames keep the raw bytes and report where decoding stopped.
    auto cut = decodePacket(raw.substr(0, 20), 1, 0, 60, "");
    CHECK(cut.info.contains("error"));
    CHECK_EQ(cut.raw.size(), size_t(20));

    // Ethernet padding beyond the IPv4 total length is not treated as payload.
    auto padded = ipv4Frame(17, udp(1000, 2000, "hi")) + std::string(10, '\0');
    CHECK_EQ(decodePacket(padded, 1, 0, uint32_t(padded.size()), "").info["payloadLength"].get<size_t>(), size_t(2));
}

void captureFiles() {
    auto a = ipv4Frame(6, tcp(1, 2, 3, 0x02, "")), b = ipv4Frame(17, udp(53000, 53, dnsQuery()));
    std::vector<Packet> in{decodePacket(a, 1, 1700000000123, uint32_t(a.size()), "eth0"), decodePacket(b, 1, 1700000000456, uint32_t(b.size() + 4), "eth0")};
    auto out = readCapture(writePcapng(in));
    CHECK_EQ(out.size(), size_t(2));
    if (out.size() == 2) {
        CHECK_EQ(out[0].raw, a); CHECK_EQ(out[1].raw, b);
        CHECK_EQ(out[0].time, int64_t(1700000000123)); CHECK_EQ(out[1].time, int64_t(1700000000456));
        CHECK_EQ(out[1].originalLength, uint32_t(b.size() + 4));
        CHECK_EQ(out[1].info["protocol"].get<std::string>(), "DNS"s);
    }

    std::string pcap; le32(pcap, 0xa1b2c3d4); le16(pcap, 2); le16(pcap, 4); le32(pcap, 0); le32(pcap, 0); le32(pcap, 65535); le32(pcap, 1);
    le32(pcap, 10); le32(pcap, 500000); le32(pcap, uint32_t(a.size())); le32(pcap, uint32_t(a.size())); pcap += a;
    auto classic = readCapture(pcap);
    CHECK_EQ(classic.size(), size_t(1));
    if (!classic.empty()) { CHECK_EQ(classic[0].time, int64_t(10500)); CHECK_EQ(classic[0].info["protocol"].get<std::string>(), "TCP"s); }

    CHECK(throws([] { readCapture("this is not a capture file"); }));
    CHECK(throws([&] { readCapture(pcap.substr(0, pcap.size() - 5)); }));
}

void streamGaps() {
    auto syn = ipv4Frame(6, tcp(40000, 80, 1000, 0x02, ""));
    auto first = ipv4Frame(6, tcp(40000, 80, 1001, 0x18, "hello "));
    auto second = ipv4Frame(6, tcp(40000, 80, 1012, 0x18, "world"));
    std::vector<Packet> ps;
    for (auto* r : {&syn, &second, &first}) { ps.push_back(decodePacket(*r, 1, 0, uint32_t(r->size()), "")); ps.back().id = ps.size(); }
    auto key = ps[0].info["key"].get<std::string>();
    auto preview = streamPreview(ps, key);
    CHECK_EQ(preview.size(), size_t(1));
    if (preview.size() == 1) {
        auto& chunks = preview[0]["chunks"];
        CHECK_EQ(chunks.size(), size_t(3));
        if (chunks.size() == 3) {
            CHECK_EQ(unbase64(chunks[0]["base64"].get<std::string>()), "hello "s);
            CHECK_EQ(chunks[1]["gap"].get<int64_t>(), int64_t(5)); // missing bytes are shown as a gap, never invented
            CHECK_EQ(unbase64(chunks[2]["base64"].get<std::string>()), "world"s);
        }
    }
}

void sessions() {
    Store s; sample(s);
    auto archive = s.archive();
    CHECK(archive["session"]["sample"].get<bool>());
    CHECK(archive["flows"].size() >= 5);
    for (auto& f : archive["flows"]) CHECK_EQ(f["source"].get<std::string>(), "sample"s);

    Store copy; copy.restore(archive);
    auto again = copy.archive();
    CHECK_EQ(again["flows"].size(), archive["flows"].size());
    CHECK_EQ(again["flows"][0]["request"]["body"]["base64"], archive["flows"][0]["request"]["body"]["base64"]);
    CHECK(again["session"]["sample"].get<bool>());

    // A broken import must leave the current session untouched.
    auto before = copy.archive()["flows"].size();
    auto noSession = archive; noSession.erase("session");
    CHECK(throws([&] { copy.restore(noSession); }));
    CHECK_EQ(copy.archive()["flows"].size(), before);
    auto dupPackets = archive;
    auto pkt = ipv4Frame(17, udp(1, 2, "x"));
    auto pj = decodePacket(pkt, 1, 0, uint32_t(pkt.size()), "").detail(); pj["id"] = 7;
    dupPackets["packets"] = json::array({pj, pj});
    CHECK(throws([&] { copy.restore(dupPackets); }));
    CHECK_EQ(copy.archive()["flows"].size(), before);
    auto badBody = archive; badBody["flows"][0]["request"]["body"]["base64"] = "@@@@";
    CHECK(throws([&] { copy.restore(badBody); }));
    CHECK(throws([&] { copy.restore(json{{"format", "other"}}); }));
}

void exports() {
    Store s;
    auto id = s.createFlow({{"method", "POST"}, {"host", "api.example"}, {"path", "/v1/x?key=secret&</script><script>alert(1)</script>"}},
                           {{"Authorization", "Bearer secret-token"}, {"Content-Type", "application/json"}});
    s.edit(id, [](Flow& f) { f.request.append("{\"a\":1}", 7); f.meta["state"] = "complete"; });
    auto redacted = redactedArchive(s.archive());
    auto& f = redacted["flows"][0];
    CHECK_EQ(f["request"]["headers"][0][1].get<std::string>(), "[redacted]"s);
    CHECK_EQ(f["request"]["headers"][1][1].get<std::string>(), "application/json"s);
    CHECK_EQ(f["request"]["body"]["base64"].get<std::string>(), ""s);
    CHECK_EQ(f["path"].get<std::string>(), "/v1/x?[redacted]"s);
    CHECK(redacted["redacted"].get<bool>());

    auto html = htmlReport(s.archive(), "body{}", "/*viewer*/", false);
    CHECK(html.find("alert(1)") == std::string::npos); // payload text only appears base64-encoded
    CHECK(html.find("/*viewer*/") != std::string::npos);

#ifdef WIRESCOPE_SOURCE_DIR
    // The viewer script is inlined into reports; these sequences would end or corrupt the script element.
    std::ifstream js(std::string(WIRESCOPE_SOURCE_DIR) + "/web/app.js", std::ios::binary);
    std::string script((std::istreambuf_iterator<char>(js)), {});
    CHECK(!script.empty());
    CHECK(lower(script).find("</script") == std::string::npos);
    CHECK(script.find("<!--") == std::string::npos);
#endif
}

// Windows process attribution is stored on the flow; the list carries only pid/name, exports may hide the rest.
void processRecord() {
    Store s;
    json who = {{"pid", 4242}, {"name", "node.exe"}, {"path", "C:\\Users\\someone\\AppData\\node.exe"},
                {"commandLine", "node.exe cli.js --api-key sk-secret"}, {"parentPid", 100}, {"parentName", "pwsh.exe"}};
    auto id = s.createFlow({{"method", "GET"}, {"host", "api.example"}, {"path", "/"}, {"process", who}});
    auto listed = s.snapshot()["flows"][0]["process"];
    CHECK_EQ(listed.size(), size_t(2));
    CHECK_EQ(listed["pid"].get<int>(), 4242);
    CHECK_EQ(listed["name"].get<std::string>(), "node.exe"s);
    CHECK(s.flow(id)["process"] == who);
    auto archive = s.archive();
    CHECK(archive["flows"][0]["process"] == who);
    Store copy; copy.restore(archive);
    CHECK(copy.flow(id)["process"] == who);  // survives .wscope round trip
    auto redacted = redactedArchive(archive)["flows"][0]["process"];
    CHECK_EQ(redacted["commandLine"].get<std::string>(), "[redacted]"s);
    CHECK_EQ(redacted["path"].get<std::string>(), "[redacted]"s);
    CHECK_EQ(redacted["pid"].get<int>(), 4242);
    CHECK_EQ(redacted["parentName"].get<std::string>(), "pwsh.exe"s);
}
}

int main() {
    for (auto& [name, fn] : std::vector<std::pair<const char*, void (*)()>>{
             {"encoding", encoding}, {"body limit", bodyLimit}, {"packets", packets}, {"capture files", captureFiles},
             {"stream gaps", streamGaps}, {"sessions", sessions}, {"exports", exports}, {"process record", processRecord}}) {
        try { fn(); } catch (const std::exception& e) { ++failures; std::cerr << name << ": unexpected exception: " << e.what() << "\n"; }
    }
    std::cout << checks << " checks, " << failures << " failures\n";
    return failures ? 1 : 0;
}
