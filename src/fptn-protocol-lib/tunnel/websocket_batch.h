/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <utility>

#include "fptn-protocol-lib/https/websocket_client/websocket_client.h"
#include "fptn-protocol-lib/tunnel/packet_types.h"

namespace fptn::tunnel {

// Two-phase admission of a packet batch into the websocket transport, shared
// by every owner of a transport: the standalone L3 plane, and the split plane
// whose transport is injected from outside (on Apple, the provider's existing
// websocket bridge, so reconnect and diagnostics keep working).
//
// Move-only: holding one keeps queue accounting reserved until it is either
// committed or destroyed, and the destructor rolls back.
class WebsocketBatchReservation {
 public:
  WebsocketBatchReservation() noexcept = default;
  WebsocketBatchReservation(fptn::protocol::https::WebsocketClientSPtr client,
      fptn::protocol::https::BatchQueueReservation queue) noexcept
      : client_(std::move(client)), queue_(std::move(queue)) {}

  WebsocketBatchReservation(WebsocketBatchReservation&&) noexcept = default;
  WebsocketBatchReservation(const WebsocketBatchReservation&) = delete;
  WebsocketBatchReservation& operator=(const WebsocketBatchReservation&) =
      delete;

  explicit operator bool() const noexcept { return client_ != nullptr; }

 private:
  friend WebsocketBatchReservation TryReserveWebsocketBatch(
      const fptn::protocol::https::WebsocketClientSPtr&, PacketBatchView,
      PacketInputResult&) noexcept;
  friend void CommitWebsocketBatch(
      PacketBatchView, WebsocketBatchReservation) noexcept;

  fptn::protocol::https::WebsocketClientSPtr client_;
  fptn::protocol::https::BatchQueueReservation queue_;
};

// Validates the batch and reserves transport queue capacity. Consumes no lease
// on any path; on failure `out_error` says why. Validation runs ahead of the
// connectivity gate so malformed input is always reported as malformed.
WebsocketBatchReservation TryReserveWebsocketBatch(
    const fptn::protocol::https::WebsocketClientSPtr& client,
    PacketBatchView packets, PacketInputResult& out_error) noexcept;

// Consumes a reservation: every lease in `packets` is released exactly once.
// A packet that fails to parse here is dropped rather than handed back,
// because the caller has already been told the batch was accepted.
void CommitWebsocketBatch(
    PacketBatchView packets, WebsocketBatchReservation reservation) noexcept;

}  // namespace fptn::tunnel
