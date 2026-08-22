find_package(GTest REQUIRED)
find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(spdlog REQUIRED)
find_package(fmt REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(jwt-cpp REQUIRED)
find_package(Boost REQUIRED COMPONENTS random filesystem)

if(WIN32)
  set(TUNTAP_LIB Wintun rpcrt4)
  add_definitions(-D_WIN32_WINNT=0x0601)
else()
  set(TUNTAP_LIB tuntap++)
endif()

set(LIBS
    GTest::gtest
    GTest::gtest_main
    Boost::boost
    Boost::random
    Boost::process
    Boost::filesystem
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    jwt-cpp::jwt-cpp
    spdlog::spdlog
    fmt::fmt
    fptn-protocol-lib_static
    ${TUNTAP_LIB})

# --- ApiClient test ---
add_executable(ApiClientTest api_client/ApiClientTest.cpp)
target_link_libraries(ApiClientTest PRIVATE ${LIBS})
add_test(NAME ApiClientTest COMMAND ApiClientTest)

# PR-LW0: tunnel engine seam (DataPlaneMode/IDataPlane/TunnelEngine).
add_executable(TunnelSeamTest tunnel/TunnelSeamTest.cpp)
target_link_libraries(TunnelSeamTest PRIVATE ${LIBS})
add_test(NAME TunnelSeamTest COMMAND TunnelSeamTest)

# R1: RouteAction verdicts and the domain routing policy.
add_executable(RoutingPolicyTest tunnel/RoutingPolicyTest.cpp)
target_link_libraries(RoutingPolicyTest PRIVATE ${LIBS})
add_test(NAME RoutingPolicyTest COMMAND RoutingPolicyTest)

# Compiled geo rule set: interval flattening, the mapped reader, and its
# refusal to touch a malformed artifact.
add_executable(GeoRuleSetTest geo/GeoRuleSetTest.cpp)
target_link_libraries(GeoRuleSetTest PRIVATE ${LIBS})
add_test(NAME GeoRuleSetTest COMMAND GeoRuleSetTest)

# The .dat container reader, the verdict map and the regex reducer.
add_executable(GeoDatParserTest geo/GeoDatParserTest.cpp)
target_link_libraries(GeoDatParserTest PRIVATE ${LIBS})
add_test(NAME GeoDatParserTest COMMAND GeoDatParserTest)

# Domain-first, address-fallback routing over a compiled rule set.
add_executable(GeoRoutingPolicyTest geo/GeoRoutingPolicyTest.cpp)
target_link_libraries(GeoRoutingPolicyTest PRIVATE ${LIBS})
add_test(NAME GeoRoutingPolicyTest COMMAND GeoRoutingPolicyTest)

# Domain list parsing, deduplication, and Git override precedence.
add_executable(GeoInputsTest geo/GeoInputsTest.cpp)
target_link_libraries(GeoInputsTest PRIVATE ${LIBS})
add_test(NAME GeoInputsTest COMMAND GeoInputsTest)

# R2: 5-tuple peek, flow table and pinned classifier rules.
add_executable(FlowClassifierTest tunnel/FlowClassifierTest.cpp)
target_link_libraries(FlowClassifierTest PRIVATE ${LIBS})
add_test(NAME FlowClassifierTest COMMAND FlowClassifierTest)

# R3: DNS snooping that attributes an address to a domain.
add_executable(DnsObserverTest tunnel/DnsObserverTest.cpp)
target_link_libraries(DnsObserverTest PRIVATE ${LIBS})
add_test(NAME DnsObserverTest COMMAND DnsObserverTest)

# PR-LW2: lwIP netif + packet pump.
if (FPTN_WITH_LWIP)
  add_executable(LwipStackTest flow/LwipStackTest.cpp)
  target_link_libraries(LwipStackTest PRIVATE ${LIBS})
  add_test(NAME LwipStackTest COMMAND LwipStackTest)

  # PR-LW3: transparent TCP frontend.
  add_executable(LwipTcpTest flow/LwipTcpTest.cpp)
  target_link_libraries(LwipTcpTest PRIVATE ${LIBS})
  add_test(NAME LwipTcpTest COMMAND LwipTcpTest)

  # PR-LW4: DIRECT TCP outbound through the tunnel engine.
  add_executable(DirectTcpFlowTest flow/DirectTcpFlowTest.cpp)
  target_link_libraries(DirectTcpFlowTest PRIVATE ${LIBS})
  add_test(NAME DirectTcpFlowTest COMMAND DirectTcpFlowTest)

  # PR-LW5: transparent UDP associations and DIRECT UDP outbound.
  add_executable(LwipUdpTest flow/LwipUdpTest.cpp)
  target_link_libraries(LwipUdpTest PRIVATE ${LIBS})
  add_test(NAME LwipUdpTest COMMAND LwipUdpTest)

  # R4/R5: split data plane, two-phase fan-out and the table-backed router.
  add_executable(SplitDataPlaneTest tunnel/SplitDataPlaneTest.cpp)
  target_link_libraries(SplitDataPlaneTest PRIVATE ${LIBS})
  add_test(NAME SplitDataPlaneTest COMMAND SplitDataPlaneTest)

  # Review regressions: ERR_ABRT paths, ingress/stop race, FIN-after-data,
  # clean-completion resource release, one-shot engine, UDP pcb retention.
  add_executable(LwipFlowRegressionTest flow/LwipFlowRegressionTest.cpp)
  target_link_libraries(LwipFlowRegressionTest PRIVATE ${LIBS})
  add_test(NAME LwipFlowRegressionTest COMMAND LwipFlowRegressionTest)
endif()
