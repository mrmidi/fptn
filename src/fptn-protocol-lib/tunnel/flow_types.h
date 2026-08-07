/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

#include <boost/asio/ip/address.hpp>

namespace fptn::tunnel {

using FlowId = std::uint64_t;

enum class TransportProtocol : std::uint8_t {
  tcp = 0,
  udp = 1,
};

enum class RouteAction : std::uint8_t {
  direct = 0,
  fptn_l4 = 1,
  block = 2,
};

enum class FlowError : std::uint8_t {
  none = 0,
  reset = 1,
  timeout = 2,
  refused = 3,
  outbound_failure = 4,
  shutdown = 5,
  unknown = 255,
};

enum class WriteResult : std::uint8_t {
  accepted = 0,
  queue_full = 1,
  flow_closed = 2,
  invalid_argument = 3,
};

struct IpEndpoint {
  boost::asio::ip::address address;
  std::uint16_t port = 0;
};

struct FlowMetadata {
  FlowId id = 0;
  TransportProtocol protocol = TransportProtocol::tcp;
  IpEndpoint source;
  IpEndpoint destination;
};

struct BufferView {
  const std::uint8_t* data = nullptr;
  std::size_t size = 0;
};

using BufferSequence = std::span<const BufferView>;
using OwnedBuffer = std::vector<std::uint8_t>;

#ifndef FPTN_OWNED_PACKET_DEFINED
#define FPTN_OWNED_PACKET_DEFINED
struct OwnedPacket {
  OwnedBuffer data;
  std::uint8_t ip_version = 0;
};

using OwnedPacketBatch = std::vector<OwnedPacket>;
#endif

// Borrowed view of an egress batch, mirroring PacketBatchView on the ingress
// side. The producer keeps ownership so it can recycle the packet buffers
// between batches; consumers must copy anything they need to outlive the call.
using OwnedPacketBatchView = std::span<const OwnedPacket>;
using PacketOutputCallback = std::function<void(OwnedPacketBatchView)>;

}  // namespace fptn::tunnel
