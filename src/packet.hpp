#pragma once
#include "core.hpp"
#include <memory>
namespace ws {
Packet decodePacket(const std::string& raw,int linkType,int64_t time,uint32_t originalLength,const std::string& device);
std::vector<Packet> readCapture(const std::string& bytes);
std::string writePcapng(const std::vector<Packet>& packets);
// Reassembles a bounded preview, preserving gaps instead of inventing missing bytes.
json streamPreview(const std::vector<Packet>&, const std::string& key);
class Capture {
public:
    explicit Capture(Store& s);
    ~Capture();
    json interfaces();
    void start(const std::string& device,const std::string& filter);
    void stop();
    json status() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
