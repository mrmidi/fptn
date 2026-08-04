/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/tunnel/tunnel_engine.h"

#include <utility>

#include "fptn-protocol-lib/tunnel/l3_tunnel_data_plane.h"

#ifdef FPTN_HAS_LWIP
#include "fptn-protocol-lib/tunnel/flow_proxy_data_plane.h"
#endif

namespace fptn::tunnel {

TunnelEngine::TunnelEngine(
    DataPlaneMode mode, std::unique_ptr<IDataPlane> data_plane)
    : mode_(mode), data_plane_(std::move(data_plane)) {}

TunnelEngine::~TunnelEngine() { Stop(); }

std::expected<std::unique_ptr<TunnelEngine>, TunnelError> TunnelEngine::Create(
    TunnelConfiguration config, TunnelCallbacks callbacks) {
  const DataPlaneMode mode = config.mode;
  switch (mode) {
    case DataPlaneMode::l3_tunnel: {
      if (config.l3.server_ip.empty() || config.l3.server_port <= 0) {
        return std::unexpected(TunnelError::invalid_configuration);
      }
      auto data_plane = std::make_unique<L3TunnelDataPlane>(
          std::move(config.l3), std::move(callbacks));
      return std::unique_ptr<TunnelEngine>(
          new TunnelEngine(mode, std::move(data_plane)));
    }
    case DataPlaneMode::flow_proxy: {
#ifdef FPTN_HAS_LWIP
      if (config.l3.tun_ipv4.empty()) {
        return std::unexpected(TunnelError::invalid_configuration);
      }
      auto data_plane = std::make_unique<FlowProxyDataPlane>(
          std::move(config), std::move(callbacks));
      return std::unique_ptr<TunnelEngine>(
          new TunnelEngine(mode, std::move(data_plane)));
#else
      break;
#endif
    }
  }
  return std::unexpected(TunnelError::unsupported_mode);
}

std::expected<void, TunnelError> TunnelEngine::Start() {
  if (started_.load(std::memory_order_acquire)) {
    return std::unexpected(TunnelError::already_running);
  }
  auto result = data_plane_->Start();
  if (result.has_value()) {
    started_.store(true, std::memory_order_release);
  }
  return result;
}

void TunnelEngine::Stop() noexcept {
  if (!started_.exchange(false, std::memory_order_acq_rel)) {
    return;
  }
  data_plane_->Stop();
}

PacketInputResult TunnelEngine::InputPackets(PacketBatchView packets) noexcept {
  if (!started_.load(std::memory_order_acquire)) {
    return PacketInputResult::transport_stopped;
  }
  return data_plane_->InputPackets(packets);
}

}  // namespace fptn::tunnel
