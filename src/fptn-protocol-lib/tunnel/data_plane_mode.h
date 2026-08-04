/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>

namespace fptn::tunnel {

enum class DataPlaneMode : std::uint8_t {
  l3_tunnel = 0,
  flow_proxy = 1,
};

constexpr const char* ToString(DataPlaneMode mode) noexcept {
  switch (mode) {
    case DataPlaneMode::l3_tunnel:
      return "L3Tunnel";
    case DataPlaneMode::flow_proxy:
      return "FlowProxy";
  }
  return "Unknown";
}

}  // namespace fptn::tunnel
