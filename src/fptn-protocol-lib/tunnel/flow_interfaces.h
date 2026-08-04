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

enum class OutboundAdmission : std::uint8_t {
  accepted = 0,
  queue_full = 1,
  flow_closed = 2,
};

class ITcpOutboundSink {
 public:
  virtual ~ITcpOutboundSink() = default;

  virtual void OnOutboundConnected(FlowId flow) = 0;
  virtual bool OnOutboundData(FlowId flow, OwnedBuffer data) = 0;
  virtual void OnOutboundFinished(FlowId flow) = 0;
  virtual void OnOutboundReset(FlowId flow, FlowError error) = 0;
  virtual void OnOutboundWritable(FlowId flow) = 0;
};

class ITcpOutbound {
 public:
  virtual ~ITcpOutbound() = default;

  virtual void Open(FlowMetadata metadata, ITcpOutboundSink& sink) = 0;
  virtual OutboundAdmission Write(FlowId flow, BufferSequence data) = 0;
  virtual void Finish(FlowId flow) = 0;
  virtual void Reset(FlowId flow) = 0;
  virtual void StackWindowOpen(FlowId flow) = 0;
};

}  // namespace fptn::tunnel
