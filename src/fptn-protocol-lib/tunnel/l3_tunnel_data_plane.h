/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <mutex>
#include <thread>

#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"
#include "fptn-protocol-lib/tunnel/i_data_plane.h"
#include "fptn-protocol-lib/tunnel/websocket_batch.h"
#include "fptn-protocol-lib/tunnel/tunnel_configuration.h"

namespace fptn::tunnel {

class L3TunnelDataPlane final : public IDataPlane {
 public:
  L3TunnelDataPlane(TunnelL3Configuration config, TunnelCallbacks callbacks);
  ~L3TunnelDataPlane() override;

  L3TunnelDataPlane(const L3TunnelDataPlane&) = delete;
  L3TunnelDataPlane& operator=(const L3TunnelDataPlane&) = delete;

  std::expected<void, TunnelError> Start() override;
  void Stop() noexcept override;

  PacketInputResult InputPackets(PacketBatchView packets) noexcept override;

 private:
  void RunThread() noexcept;

  TunnelL3Configuration config_;
  TunnelCallbacks callbacks_;

  mutable std::mutex mutex_;
  fptn::protocol::https::WebsocketClientSPtr client_;
  std::thread run_thread_;
  std::atomic<bool> running_{false};
};

}  // namespace fptn::tunnel
