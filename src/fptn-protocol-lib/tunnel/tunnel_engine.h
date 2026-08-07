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
#ifdef FPTN_HAS_LWIP
#include "fptn-protocol-lib/tunnel/split_data_plane.h"
#endif
#include "fptn-protocol-lib/tunnel/tunnel_error.h"

namespace fptn::tunnel {

class TunnelEngine final {
 public:
  static std::expected<std::unique_ptr<TunnelEngine>, TunnelError> Create(
      TunnelConfiguration config, TunnelCallbacks callbacks);

#ifdef FPTN_HAS_LWIP
  // Split mode only. The websocket transport is injected by the platform
  // layer so the one it already manages (with reconnect and diagnostics)
  // keeps carrying fptn-verdict traffic, and a reconnect leaves lwIP alone.
  static std::expected<std::unique_ptr<TunnelEngine>, TunnelError> CreateSplit(
      TunnelConfiguration config, TunnelCallbacks callbacks,
      TransportProvider transport);

  // Split mode only; null otherwise. The platform layer needs the plane to
  // feed it the inbound DNS tap. Borrowed -- the engine keeps ownership.
  SplitDataPlane* SplitPlane() const noexcept { return split_plane_; }
#endif

  ~TunnelEngine();

  TunnelEngine(const TunnelEngine&) = delete;
  TunnelEngine& operator=(const TunnelEngine&) = delete;

  std::expected<void, TunnelError> Start();
  void Stop() noexcept;

  // PacketLease batch ownership contract (see packet_types.h): on
  // `accepted` the engine owns every lease and releases each exactly once;
  // on any other result the caller still owns every lease.
  PacketInputResult InputPackets(PacketBatchView packets) noexcept;

  // Diagnostic snapshot of the active data plane; zeroed for planes that
  // keep no flow state.
  FlowCounters Counters() const noexcept;

  DataPlaneMode mode() const noexcept { return mode_; }
  bool IsStarted() const noexcept {
    return started_.load(std::memory_order_acquire);
  }

 private:
  TunnelEngine(DataPlaneMode mode, std::unique_ptr<IDataPlane> data_plane);

  DataPlaneMode mode_;
  std::unique_ptr<IDataPlane> data_plane_;
  std::atomic<bool> started_{false};
#ifdef FPTN_HAS_LWIP
  SplitDataPlane* split_plane_ = nullptr;
#endif
};

}  // namespace fptn::tunnel
