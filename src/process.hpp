#pragma once
#include "core.hpp"

namespace ws {

// 프록시로 들어온 TCP 연결을 "누가" 열었는지 찾는다 (Windows 전용).
//
//   app (curl.exe, node.exe ...)          WireScope
//   127.0.0.1:52344  ──── TCP ────>  127.0.0.1:18080
//   ^ client endpoint                ^ proxy endpoint
//
// Windows TCP 연결 표에는 loopback 연결의 양쪽 끝이 따로 한 줄씩 있다.
// (local=client, remote=proxy) 인 줄의 owning PID 가 그 앱이다.
//
// 반환: {"pid","name","path","commandLine","parentPid","parentName","source"} 중 얻은 것.
//       표에서 못 찾았거나 프로세스를 못 열면 "error" 에 이유를 남긴다 (pid 는 있을 수 있음).
//       Windows 가 아니면 null (macOS/Linux 는 목표 OS 가 아니라 구현하지 않음).
json processForConnection(const std::string& clientEndpoint, const std::string& proxyEndpoint);

}  // namespace ws
