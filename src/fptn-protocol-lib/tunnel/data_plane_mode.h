/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>

namespace fptn::tunnel {

enum class DataPlaneMode : std::uint8_t {
  // All traffic via the server. No lwIP. This is the "FPTN only" product mode
  // and the path that has been shipping.
  l3_tunnel = 0,
  // Direct only, no server. Development and profiling only -- it must never be
  // reachable in a release build, since it leaves the user's real IP exposed.
  flow_proxy = 1,
  // Direct and FPTN per policy: the "Split" product mode.
  split = 2,
};

constexpr const char* ToString(DataPlaneMode mode) noexcept {
  switch (mode) {
    case DataPlaneMode::l3_tunnel:
      return "L3Tunnel";
    case DataPlaneMode::flow_proxy:
      return "FlowProxy";
    case DataPlaneMode::split:
      return "Split";
  }
  return "Unknown";
}

}  // namespace fptn::tunnel
