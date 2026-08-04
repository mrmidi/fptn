/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <expected>

#include "fptn-protocol-lib/tunnel/packet_types.h"
#include "fptn-protocol-lib/tunnel/tunnel_error.h"

namespace fptn::tunnel {

class IDataPlane {
 public:
  virtual ~IDataPlane() = default;

  virtual std::expected<void, TunnelError> Start() = 0;
  virtual void Stop() noexcept = 0;

  virtual PacketInputResult InputPackets(PacketBatchView packets) noexcept = 0;
};

}  // namespace fptn::tunnel
