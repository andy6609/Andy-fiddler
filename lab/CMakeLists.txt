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
  set_target_properties(${name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lab)
endfunction()
lab_version(v1_flow_recorder)
lab_version(v2_tls_recorder LIBS OpenSSL::SSL OpenSSL::Crypto)
lab_version(v3_h2_observer LIBS OpenSSL::SSL OpenSSL::Crypto ${NGHTTP2_LIBRARY})
lab_version(v4_packet_decoder)
lab_version(v5_tcp_stream)
