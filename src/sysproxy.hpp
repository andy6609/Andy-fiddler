#pragma once
#include "core.hpp"
#include <mutex>

namespace ws {

// Windows 사용자 프록시 설정(WinINET)을 WireScope 로 돌렸다가 원래대로 되돌린다.
// "설정 > 네트워크 및 인터넷 > 프록시 > 수동 프록시 설정" 과 같은 값이다.
//
// 원칙
//   - 사용자가 버튼을 눌렀을 때만 바꾼다 (실행만으로는 절대 안 바꿈).
//   - 바꾸기 전 값을 <data>/system-proxy-backup.json 에 먼저 저장한다.
//   - 끄기, 프록시 중지, 정상 종료 때 백업으로 되돌린다.
//   - 비정상 종료로 백업 파일이 남아 있으면 다음 실행에서 status().leftover=true -> 화면이 복원을 권한다.
//
// 이 설정을 따르는 것은 WinINET/시스템 설정을 읽는 클라이언트뿐이다 (브라우저, 많은 Windows 앱,
// Python urllib 등). curl 이나 Node.js 기반 CLI 는 따르지 않는다 -> 환경 변수(HTTPS_PROXY)를 써야 한다.
class SystemProxy {
public:
    explicit SystemProxy(std::string dataDirectory);
    ~SystemProxy();  // 이번 실행에서 켰다면 되돌린다
    json status() const;
    void enable(uint16_t port);
    void restore();
    bool owned() const;

private:
    std::string directory_;
    mutable std::mutex mutex_;
    bool enabledThisRun_ = false;
};

}  // namespace ws
