/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include <yaff/buffer.h>
#include <string>
#include <utility>

#include <boost/beast/core/flat_buffer.hpp>

#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/protocol/payload.h"

namespace fptn::protocol::yaff {

using protocol::BatchProtoPayload;
using protocol::ProtoPayload;
using protocol::ProtoPayloadOpt;

// Holds YAFF's move-only serialized allocation until the asynchronous
// WebSocket write completes. This avoids copying the complete frame into a
// ProtoPayload vector after serialization.
class SerializedPacketBatch {
 public:
  explicit SerializedPacketBatch(::yaff::DetachedBuffer buffer) noexcept
      : buffer_(std::move(buffer)) {}

  const std::uint8_t* data() const noexcept {
    return reinterpret_cast<const std::uint8_t*>(buffer_.Data());
  }
  std::size_t size() const noexcept { return buffer_.Size(); }

 private:
  ::yaff::DetachedBuffer buffer_;
};

std::optional<SerializedPacketBatch> SerializeBatchIPPacketOwned(
    common::network::BatchIPPacketPtr packets);

BatchProtoPayload DeserializeBatchIPPacket(
    const boost::beast::flat_buffer& buffer);
ProtoPayloadOpt SerializeBatchIPPacket(
    common::network::BatchIPPacketPtr packets);

std::optional<std::string> SerializeIPAssignmentMessage(
    const std::string& ip_v4, const std::string& ip_v6);
std::optional<std::pair<std::string, std::string>>
DeserializeIPAssignmentMessage(const std::string& message);

}  // namespace fptn::protocol::yaff
