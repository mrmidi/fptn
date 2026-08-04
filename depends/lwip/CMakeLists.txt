project(fptn_lwip LANGUAGES C)

# PR-LW1: optional HEV lwIP stack for the FlowProxy data plane.
# Built as an OBJECT library so its objects are absorbed into
# fptn-protocol-lib_static.a (the Conan package ships that single archive).
# Upstream pin + license record: PATCHES.md in this directory.

set(FPTN_LWIP_SRC "${FPTN_LWIP_SOURCE_DIR}/src")

set(FPTN_LWIP_SOURCES
    "${FPTN_LWIP_SRC}/core/def.c"
    "${FPTN_LWIP_SRC}/core/inet_chksum.c"
    "${FPTN_LWIP_SRC}/core/init.c"
    "${FPTN_LWIP_SRC}/core/ip.c"
    "${FPTN_LWIP_SRC}/core/mem.c"
    "${FPTN_LWIP_SRC}/core/memp.c"
    "${FPTN_LWIP_SRC}/core/netif.c"
    "${FPTN_LWIP_SRC}/core/pbuf.c"
    "${FPTN_LWIP_SRC}/core/stats.c"
    "${FPTN_LWIP_SRC}/core/sys.c"
    "${FPTN_LWIP_SRC}/core/tcp.c"
    "${FPTN_LWIP_SRC}/core/tcp_in.c"
    "${FPTN_LWIP_SRC}/core/tcp_out.c"
    "${FPTN_LWIP_SRC}/core/timeouts.c"
    "${FPTN_LWIP_SRC}/core/udp.c"
    "${FPTN_LWIP_SRC}/core/ipv4/icmp.c"
    "${FPTN_LWIP_SRC}/core/ipv4/ip4.c"
    "${FPTN_LWIP_SRC}/core/ipv4/ip4_addr.c"
    "${FPTN_LWIP_SRC}/core/ipv4/ip4_frag.c"
    "${FPTN_LWIP_SRC}/core/ipv6/icmp6.c"
    "${FPTN_LWIP_SRC}/core/ipv6/inet6.c"
    "${FPTN_LWIP_SRC}/core/ipv6/ip6.c"
    "${FPTN_LWIP_SRC}/core/ipv6/ip6_addr.c"
    "${FPTN_LWIP_SRC}/core/ipv6/ip6_frag.c"
    "${FPTN_LWIP_SRC}/core/ipv6/nd6.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/fptn_lwip_port.c")

add_library(fptn_lwip OBJECT ${FPTN_LWIP_SOURCES})

# Third-party sources: suppress project-wide -Wall -Werror -pedantic.
target_compile_options(fptn_lwip PRIVATE -w)

target_include_directories(fptn_lwip PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${FPTN_LWIP_SRC}/include")
