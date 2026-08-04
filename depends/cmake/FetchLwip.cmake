include(FetchContent)

# HEV lwIP fork: transparent TCP/UDP (NETIF_FLAG_PRETEND_*), baseline lwIP 2.2.1.
# Canonical: https://gitlab.com/hev/lwip — fetched from the GitHub mirror
# (same commits; matches the repo's existing GitHub-based FetchContent deps).
# Pin record + license inventory: depends/lwip/PATCHES.md
set(FPTN_LWIP_GIT_REPOSITORY
    "https://github.com/heiher/lwip.git"
    CACHE STRING "HEV lwIP fork git repository")
set(FPTN_LWIP_GIT_TAG
    "2a11c14c7a32887af25a034e82ef18b0b12076ac"
    CACHE STRING "Pinned HEV lwIP commit")

FetchContent_Declare(fptn_lwip
    GIT_REPOSITORY ${FPTN_LWIP_GIT_REPOSITORY}
    GIT_TAG ${FPTN_LWIP_GIT_TAG})

FetchContent_Populate(fptn_lwip)

# Deterministic FetchContent layout (populate variables are unreliable here;
# same convention as FetchBase64.cmake).
set(FPTN_LWIP_SOURCE_DIR
    "${CMAKE_BINARY_DIR}/_deps/fptn_lwip-src"
    CACHE INTERNAL "Populated HEV lwIP source directory")

add_subdirectory(
    "${CMAKE_CURRENT_LIST_DIR}/../lwip"
    "${CMAKE_BINARY_DIR}/depends/lwip")
