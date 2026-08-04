/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>

namespace fptn::tunnel {

enum class TunnelError : std::uint8_t {
  invalid_configuration = 1,
  unsupported_mode = 2,
  already_running = 3,
  start_failed = 4,
};

constexpr const char* ToString(TunnelError error) noexcept {
  switch (error) {
    case TunnelError::invalid_configuration:
      return "InvalidConfiguration";
    case TunnelError::unsupported_mode:
      return "UnsupportedMode";
    case TunnelError::already_running:
      return "AlreadyRunning";
    case TunnelError::start_failed:
      return "StartFailed";
  }
  return "Unknown";
}

}  // namespace fptn::tunnel
