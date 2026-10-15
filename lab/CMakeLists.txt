# lab/ — WireScope 를 만들기 전/옆에서 개념 하나씩 떼어 만든 학습용 버전들.
# 각 버전은 .cpp 하나 + 공용 헤더(common/lab_net.hpp). 제품 코드(src/)와 섞지 않는다.

function(lab_version name)
  cmake_parse_arguments(LAB "" "" "LIBS" ${ARGN})
  add_executable(${name} ${name}/${name}.cpp)
  target_include_directories(${name} PRIVATE common ${CMAKE_SOURCE_DIR}/third_party ${NGHTTP2_INCLUDE_DIR})
  target_link_libraries(${name} PRIVATE Threads::Threads ${LAB_LIBS})
  if(WIN32)
    target_link_libraries(${name} PRIVATE ws2_32)
  endif()
  if(MSVC)
    # /utf-8: 소스의 한국어 주석/문자열을 UTF-8 로 읽게 한다 (없으면 한국어 Windows 는 CP949 로 읽어 깨진다).
    # _CRT_SECURE_NO_WARNINGS: fopen/localtime/getenv 의 C4996 "안전하지 않음" 경고 끔 (학습용 코드).
    target_compile_options(${name} PRIVATE /utf-8 /W3)
    target_compile_definitions(${name} PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
  endif()
  # $<1:...> 생성기 식: Visual Studio 같은 multi-config 생성기가 lab/Release/ 를 덧붙이지 않게 한다
  # (tests/lab_smoke.py 는 <build>/lab/<이름> 을 찾는다).
  set_target_properties(${name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY $<1:${CMAKE_BINARY_DIR}/lab>)
endfunction()
lab_version(v1_flow_recorder)
lab_version(v2_tls_recorder LIBS OpenSSL::SSL OpenSSL::Crypto)
lab_version(v3_h2_observer LIBS OpenSSL::SSL OpenSSL::Crypto ${NGHTTP2_LIBRARY})
lab_version(v4_packet_decoder)
lab_version(v5_tcp_stream)
# v6: live capture links libpcap (macOS/Linux) or Npcap SDK's wpcap (Windows). Skipped if not found.
if(WIN32)
  find_library(LAB_PCAP_LIBRARY wpcap)
else()
  set(LAB_PCAP_LIBRARY ${PCAP_LIBRARY})
endif()
if(LAB_PCAP_LIBRARY)
  lab_version(v6_live_capture LIBS ${LAB_PCAP_LIBRARY})
else()
  message(STATUS "lab: v6_live_capture skipped (no pcap/wpcap library)")
endif()
lab_version(v7_inspector_api)
lab_version(v8_diff_report)
