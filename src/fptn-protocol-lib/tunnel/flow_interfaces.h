/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include "fptn-protocol-lib/tunnel/flow_types.h"
#include "fptn-protocol-lib/tunnel/packet_types.h"

namespace fptn::tunnel {

class INetworkStack {
 public:
  virtual ~INetworkStack() = default;

  virtual PacketInputResult InputPackets(PacketBatchView packets) noexcept = 0;

  virtual WriteResult WriteTcp(FlowId flow, BufferSequence data) noexcept = 0;
  virtual void FinishTcp(FlowId flow) noexcept = 0;
  virtual void ResetTcp(FlowId flow) noexcept = 0;

  virtual WriteResult WriteUdp(
      FlowId flow, IpEndpoint source, BufferView payload) noexcept = 0;
};

class IFlowEventSink {
 public:
  virtual ~IFlowEventSink() = default;

  virtual void OnTcpOpen(FlowMetadata metadata) = 0;
  virtual void OnTcpData(FlowId flow, OwnedBuffer data) = 0;
  virtual void OnTcpHalfClose(FlowId flow) = 0;
  virtual void OnTcpReset(FlowId flow, FlowError error) = 0;

  virtual void OnUdpDatagram(FlowMetadata metadata, OwnedBuffer payload) = 0;
};

class IFlowRouter {
 public:
  virtual ~IFlowRouter() = default;

  virtual RouteAction Match(const FlowMetadata& metadata) = 0;
};

}  // namespace fptn::tunnel
