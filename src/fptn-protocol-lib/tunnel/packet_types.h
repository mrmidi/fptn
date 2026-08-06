/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <span>

namespace fptn::tunnel {

// A borrowed view of one ingress packet plus the ownership handle for its
// backing storage. `bytes` must stay valid until `release` is invoked.
//
// Batch ownership contract for every InputPackets() implementation:
//   accepted          ownership of every lease's owner transfers to the
//                     engine; the engine invokes release exactly once per
//                     lease;
//   any other result  ownership of every lease remains with the caller,
//                     and the engine has not invoked any release.
struct PacketLease {
  const std::uint8_t* bytes = nullptr;
  std::uint32_t length = 0;
  std::uint8_t ip_version = 0;
  void* owner = nullptr;
  void (*release)(void* owner) noexcept = nullptr;
};

using PacketBatchView = std::span<const PacketLease>;

inline void ReleasePacketLease(PacketLease& lease) noexcept {
  if (lease.release != nullptr && lease.owner != nullptr) {
    lease.release(lease.owner);
  }
  lease = PacketLease{};
}

inline void ReleasePacketBatch(PacketBatchView batch) noexcept {
  for (const auto& lease : batch) {
    if (lease.release != nullptr && lease.owner != nullptr) {
      lease.release(lease.owner);
    }
  }
}

enum class PacketInputResult : std::uint8_t {
  accepted = 0,
  queue_full = 1,
  transport_stopped = 2,
  invalid_packet = 3,
};

}  // namespace fptn::tunnel
