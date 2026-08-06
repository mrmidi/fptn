/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <expected>
#include <memory>

#include "fptn-protocol-lib/tunnel/data_plane_mode.h"
#include "fptn-protocol-lib/tunnel/i_data_plane.h"
#include "fptn-protocol-lib/tunnel/packet_types.h"
#include "fptn-protocol-lib/tunnel/tunnel_configuration.h"
#include "fptn-protocol-lib/tunnel/tunnel_error.h"

namespace fptn::tunnel {

class TunnelEngine final {
 public:
  static std::expected<std::unique_ptr<TunnelEngine>, TunnelError> Create(
      TunnelConfiguration config, TunnelCallbacks callbacks);

  ~TunnelEngine();

  TunnelEngine(const TunnelEngine&) = delete;
  TunnelEngine& operator=(const TunnelEngine&) = delete;

  std::expected<void, TunnelError> Start();
  void Stop() noexcept;

  // PacketLease batch ownership contract (see packet_types.h): on
  // `accepted` the engine owns every lease and releases each exactly once;
  // on any other result the caller still owns every lease.
  PacketInputResult InputPackets(PacketBatchView packets) noexcept;

  DataPlaneMode mode() const noexcept { return mode_; }
  bool IsStarted() const noexcept {
    return started_.load(std::memory_order_acquire);
  }

 private:
  TunnelEngine(DataPlaneMode mode, std::unique_ptr<IDataPlane> data_plane);

  DataPlaneMode mode_;
  std::unique_ptr<IDataPlane> data_plane_;
  std::atomic<bool> started_{false};
};

}  // namespace fptn::tunnel
