/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/tunnel/websocket_batch.h"

#include <utility>

#include "common/network/ip_packet.h"

namespace fptn::tunnel {

WebsocketBatchReservation TryReserveWebsocketBatch(
    const fptn::protocol::https::WebsocketClientSPtr& client,
    PacketBatchView packets, PacketInputResult& out_error) noexcept {
  if (!client) {
    out_error = PacketInputResult::transport_stopped;
    return {};
  }

  std::uint64_t total_bytes = 0;
  for (const auto& lease : packets) {
    bool valid = lease.bytes != nullptr && lease.length != 0;
    if (valid && lease.ip_version != 0 && lease.ip_version != 4 &&
        lease.ip_version != 6) {
      valid = false;
    }
    if (valid) {
      // Header-only admission check (mirrors TrySendPacketBytes): avoid an
      // allocation for malformed/non-IP input.
      const std::uint8_t version = lease.bytes[0] >> 4;
      if (lease.length < 20 ||
          (version != 4 && (version != 6 || lease.length < 40))) {
        valid = false;
      }
    }
    if (!valid) {
      client->NoteRejectedBeforeCopy(packets.size(), total_bytes);
      out_error = PacketInputResult::invalid_packet;
      return {};
    }
    total_bytes += lease.length;
  }

  // Admission happens here, not at commit time: until the transport is
  // connected there is nothing to drain the queue, so accepting packets would
  // buffer them indefinitely and hide the not-connected state from the caller.
  if (!client->IsStarted()) {
    out_error = PacketInputResult::transport_stopped;
    return {};
  }

  auto queue = client->TryReserveBatch(packets.size(), total_bytes);
  if (!queue) {
    out_error = PacketInputResult::queue_full;
    return {};
  }
  return WebsocketBatchReservation(client, std::move(queue));
}

void CommitWebsocketBatch(
    PacketBatchView packets, WebsocketBatchReservation reservation) noexcept {
  auto& client = reservation.client_;
  for (const auto& lease : packets) {
    reservation.queue_.ForgetPacket(lease.length);
    try {
      fptn::common::network::IPPacketData storage(
          lease.bytes, lease.bytes + lease.length);
      auto packet = fptn::common::network::IPPacket::Parse(std::move(storage));
      if (!packet) {
        client->NoteRejectedBeforeCopy(1, lease.length);
        continue;
      }
      client->NoteAdmissionCopy(lease.length);
      client->EnqueueReservedPacket(std::move(packet), lease.length);
    } catch (...) {
      client->NoteRejectedBeforeCopy(1, lease.length);
    }
  }
  reservation.queue_.Commit();
  ReleasePacketBatch(packets);
}

}  // namespace fptn::tunnel
