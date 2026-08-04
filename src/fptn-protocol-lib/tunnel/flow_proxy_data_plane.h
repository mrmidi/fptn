/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <memory>

#include "fptn-protocol-lib/flow/direct_tcp_outbound.h"
#include "fptn-protocol-lib/flow/direct_udp_outbound.h"
#include "fptn-protocol-lib/flow/lwip_stack.h"
#include "fptn-protocol-lib/tunnel/i_data_plane.h"
#include "fptn-protocol-lib/tunnel/tunnel_configuration.h"
#include "fptn-protocol-lib/tunnel/tunnel_runtime.h"

namespace fptn::tunnel {

class FlowProxyDataPlane final : public IDataPlane {
 public:
  FlowProxyDataPlane(TunnelConfiguration config, TunnelCallbacks callbacks);
  ~FlowProxyDataPlane() override;

  FlowProxyDataPlane(const FlowProxyDataPlane&) = delete;
  FlowProxyDataPlane& operator=(const FlowProxyDataPlane&) = delete;

  std::expected<void, TunnelError> Start() override;
  void Stop() noexcept override;

  PacketInputResult InputPackets(PacketBatchView packets) noexcept override;

 private:
  struct DirectRouter final : IFlowRouter {
    RouteAction Match(const FlowMetadata&) override {
      return RouteAction::direct;
    }
  };

  struct NullEventSink final : IFlowEventSink {
    void OnTcpOpen(FlowMetadata) override {}
    void OnTcpData(FlowId, OwnedBuffer) override {}
    void OnTcpHalfClose(FlowId) override {}
    void OnTcpReset(FlowId, FlowError) override {}
    void OnUdpDatagram(FlowMetadata, OwnedBuffer) override {}
  };

  TunnelConfiguration config_;
  TunnelCallbacks callbacks_;
  TunnelRuntime runtime_;

  std::unique_ptr<DirectRouter> router_;
  std::unique_ptr<NullEventSink> event_sink_;
  std::unique_ptr<flow::DirectTcpOutbound> tcp_outbound_;
  std::unique_ptr<flow::DirectUdpOutbound> udp_outbound_;
  std::unique_ptr<flow::LwipStack> stack_;

  std::atomic<bool> started_{false};
};

}  // namespace fptn::tunnel
