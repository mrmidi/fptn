project(fptn-protocol-lib LANGUAGES CXX)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

include(../../depends/cmake/NtpClient.cmake)
include(../../depends/cmake/CamouflageTLS.cmake)
find_package(YaFF CONFIG REQUIRED)
if (IOS)
  find_library(SECURITY Security)
  find_library(CFNETWORK CFNetwork)
  find_library(SYSTEMCONFIGURATION SystemConfiguration)

  add_compile_definitions(FPTN_USER_OS=\"iOS\")
elseif(__ANDROID__)
  add_compile_definitions(FPTN_USER_OS=\"Android\")
elseif(APPLE)
  add_compile_definitions(FPTN_USER_OS=\"MacOS\")
elseif(WIN32)
  add_compile_definitions(FPTN_USER_OS=\"Windows\")
elseif(UNIX)
  add_compile_definitions(FPTN_USER_OS=\"Linux\")
else()
  message(FATAL_ERROR "Unsupported platform")
endif()

find_package(absl REQUIRED)
find_package(protobuf REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)
find_package(re2 REQUIRED)
if (FPTN_WITH_MIMALLOC)
  find_package(mimalloc REQUIRED)
endif()

find_package(Boost REQUIRED COMPONENTS random filesystem nowide locale)
find_package(ZLIB REQUIRED)
find_package(nlohmann_json REQUIRED)

if (FPTN_WITH_LIBIDN2)
  find_package(libidn2 REQUIRED)
endif ()

include_directories(${nlohmann_json_INCLUDE_DIRS})

# include
if(ABSL_INCLUDE_DIRS)
  include_directories(${ABSL_INCLUDE_DIRS})
endif()
if(absl_INCLUDE_DIRS)
  include_directories(${absl_INCLUDE_DIRS})
endif()

if(PROTOBUF_INCLUDE_DIR)
  include_directories(${PROTOBUF_INCLUDE_DIR})
endif()
if(protobuf_INCLUDE_DIRS)
  include_directories(${protobuf_INCLUDE_DIRS})
endif()
if(Protobuf_INCLUDE_DIRS)
  include_directories(${Protobuf_INCLUDE_DIRS})
endif()
if(CONAN_INCLUDE_DIRS_PROTOBUF)
  include_directories(${CONAN_INCLUDE_DIRS_PROTOBUF})
endif()
include_directories(${SOURCE_DIR} ${INCLUDE_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR}/fptn_protocol)
include_directories(${CMAKE_BINARY_DIR}/src/fptn-protocol-lib/protocol)
include_directories("${CMAKE_CURRENT_BINARY_DIR}/protocol")

# Generate C++ source and header files from the .proto files
set(protobuf_files protocol/protocol.proto)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${protobuf_files})

# Generate YaFF serialization code from the same .proto file
configure_file(protocol/protocol.proto ${CMAKE_CURRENT_BINARY_DIR}/protocol.proto COPYONLY)
yaff_generate(
  PROTOS ${CMAKE_CURRENT_BINARY_DIR}/protocol.proto
  IMPORT_DIRS ${CMAKE_CURRENT_BINARY_DIR}
  OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}
  OUT_VAR YAFF_SRCS
)
set_source_files_properties(${YAFF_SRCS} PROPERTIES SKIP_CLANG_TIDY ON)
if(MSVC)
  set_source_files_properties(${YAFF_SRCS} protocol/yaff/yaff_serializer.cpp
      PROPERTIES COMPILE_OPTIONS "/WX-")
else()
  set_source_files_properties(${YAFF_SRCS} protocol/yaff/yaff_serializer.cpp
      PROPERTIES COMPILE_OPTIONS "-Wno-error")
endif()

# --- disable clang-tidy for protobuf generated code ---
set_source_files_properties($<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/protocol.pb.h> PROPERTIES SKIP_CLANG_TIDY ON)
set_source_files_properties($<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/protocol.pb.сс> PROPERTIES SKIP_CLANG_TIDY ON)
set(DISABLE_TIDY_DIR "${CMAKE_BINARY_DIR}/src/fptn-protocol-lib/protocol/")
file(MAKE_DIRECTORY "${DISABLE_TIDY_DIR}")
file(
  WRITE "${DISABLE_TIDY_DIR}/.clang-tidy"
  "Checks: '-*,readability-inconsistent-declaration-parameter-name'
WarningsAsErrors: ''
    ")

set(FPTN_CLIENT_PROTOCOL_SOURCES
    ${PROTO_SRCS}
    ${PROTO_HDRS}
    ${YAFF_SRCS}
    https/api_client/api_client.h
    https/api_client/api_client.cpp
    https/io_runtime/io_runtime.h
    https/io_runtime/io_runtime.cpp
    https/obfuscator/methods/tls/tls_obfuscator.cpp
    https/obfuscator/methods/tls/tls_obfuscator.h
    https/obfuscator/methods/tls2/tls_obfuscator2.cpp
    https/obfuscator/methods/tls2/tls_obfuscator2.h
    https/obfuscator/methods/obfuscator_interface.h
    https/obfuscator/tcp_stream/tcp_stream.h
    https/utils/tls/tls.h
    https/utils/tls/tls.cpp
    https/websocket_client/websocket_client.h
    https/websocket_client/websocket_client.cpp
    protocol/payload.h
    protocol/protobuf/protobuf_serializer.h
    protocol/protobuf/protobuf_serializer.cpp
    protocol/yaff/yaff_serializer.h
    protocol/yaff/yaff_serializer.cpp
    time/time_provider.h
    time/time_provider.cpp
    tunnel/data_plane_mode.h
    tunnel/flow_interfaces.h
    tunnel/flow_types.h
    tunnel/i_data_plane.h
    tunnel/l3_tunnel_data_plane.h
    tunnel/l3_tunnel_data_plane.cpp
    tunnel/packet_types.h
    tunnel/tunnel_configuration.h
    tunnel/tunnel_engine.h
    tunnel/tunnel_engine.cpp
    tunnel/tunnel_error.h
    https/obfuscator/methods/detector.h)

add_library("${PROJECT_NAME}_static" STATIC ${FPTN_CLIENT_PROTOCOL_SOURCES})

# PR-LW2: lwIP flow-proxy stack (optional capability).
if (FPTN_WITH_LWIP)
  target_sources("${PROJECT_NAME}_static" PRIVATE
      flow/lwip_stack.h
      flow/lwip_stack.cpp
      flow/lwip_tcp.cpp
      flow/lwip_udp.cpp
      flow/direct_tcp_outbound.h
      flow/direct_tcp_outbound.cpp
      flow/direct_udp_outbound.h
      flow/direct_udp_outbound.cpp
      flow/pbuf_buffer_sequence.h
      tunnel/tunnel_runtime.h
      tunnel/tunnel_runtime.cpp
      tunnel/flow_proxy_data_plane.h
      tunnel/flow_proxy_data_plane.cpp)
endif()

# PR1A: iOS socket buffer experiment parameter.
# 0 = kernel default. Test variants:
#   cmake -DFPTN_IOS_SOCKET_BUFFER_BYTES=262144  (256 KiB)
#   cmake -DFPTN_IOS_SOCKET_BUFFER_BYTES=524288  (512 KiB)
set(FPTN_IOS_SOCKET_BUFFER_BYTES 0 CACHE STRING
    "Requested iOS TCP send/receive buffer size in bytes; 0 uses kernel default")
if(FPTN_IOS_SOCKET_BUFFER_BYTES GREATER 0)
  target_compile_definitions("${PROJECT_NAME}_static" PRIVATE
      FPTN_IOS_SOCKET_BUFFER_BYTES=${FPTN_IOS_SOCKET_BUFFER_BYTES})
endif()

foreach(target "${PROJECT_NAME}_static")
  if(FPTN_WITH_LIBIDN2)
    set(LIBIDN2_LIB libidn2::libidn2)
  else()
    set(LIBIDN2_LIB "")
  endif()
  
  if(MSVC)
    target_compile_options(${target} PRIVATE /wd4100 /wd4702) # disable warning C4100
  endif()

  if(IOS)
    set(IOS_LIBS "${SECURITY} ${CFNETWORK} ${SYSTEMCONFIGURATION} -framework Foundation z resolv")
  else()
    set(IOS_LIBS "")
  endif()

  if (IOS)
    set_target_properties(${target}
      PROPERTIES
          CXX_STANDARD 23
          CXX_STANDARD_REQUIRED ON
          CXX_EXTENSIONS OFF
          XCODE_ATTRIBUTE_ENABLE_BITCODE "NO"
          XCODE_ATTRIBUTE_ONLY_ACTIVE_ARCH "NO"
          XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ""
    )
  endif()

  target_include_directories(${target} INTERFACE ${CMAKE_CURRENT_BINARY_DIR} protobuf::protobuf)
  target_link_libraries(
    ${target}
    ${Protobuf_LIBRARIES}
    ${protobuf_LIBRARIES}
    protobuf::protobuf
    yaff::core
    yaff::proto
    ZLIB::ZLIB
    Boost::boost
    Boost::nowide
    Boost::random
    Boost::locale
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    fmt::fmt
    re2::re2
    ntp_client
    camouflage-tls
    ${LIBIDN2_LIB}
    ${IOS_LIBS}
  )

  if (FPTN_WITH_MIMALLOC)
    target_link_libraries(${target} mimalloc-static)
  endif()

  # PR-LW1: absorb the lwIP objects into this archive and advertise the
  # capability to consumers (Conan mirrors the define via cpp_info).
  if (FPTN_WITH_LWIP)
    target_link_libraries(${target} fptn_lwip)
    target_compile_definitions(${target} PUBLIC FPTN_HAS_LWIP=1)
  endif()
endforeach()
