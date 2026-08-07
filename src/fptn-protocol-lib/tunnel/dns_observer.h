/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

#include "common/network/ip_packet.h"

#include "fptn-protocol-lib/tunnel/flow_classifier.h"

namespace fptn::tunnel {

struct DnsObserverConfiguration {
  // A one-second TTL would evict a mapping while the connection it describes
  // is still being set up, and a week-long one would pin a stale answer, so
  // the record's own TTL is clamped into this range.
  std::chrono::seconds min_ttl{30};
  std::chrono::seconds max_ttl{3600};
  // Bounds the map; the oldest-expiring entries are dropped once reached.
  std::size_t max_entries = 4096;
};

struct DnsObserverCounters {
  std::uint64_t responses_parsed = 0;
  std::uint64_t mappings_recorded = 0;
  std::uint64_t mappings_expired = 0;
  std::uint64_t evictions = 0;
  std::uint64_t entries = 0;
};

// Records `IP -> domain` from the DNS answers flowing back through the
// tunnel, so a later SYN to that IP can be attributed to a name.
//
// This is what keeps pass-through routing possible: unlike FakeIP, it never
// rewrites a destination, so an `fptn` verdict can still forward the original
// packet untouched. It is strictly read-only -- it neither modifies nor delays
// any packet.
//
// Known limits, accepted deliberately: answers are resolved server-side (a CDN
// may return a PoP near the server), encrypted DNS (DoH/DoT) is invisible and
// falls back to the default verdict, and an IP-literal connection has no name
// to attribute.
class DnsObserver final : public IDomainAttribution {
 public:
  explicit DnsObserver(DnsObserverConfiguration config = {});

  DnsObserver(const DnsObserver&) = delete;
  DnsObserver& operator=(const DnsObserver&) = delete;

  // Tap points. Both ignore anything that is not a DNS response.
  void Observe(const fptn::common::network::BatchIPPacketPtr& packets);
  void ObservePacket(const std::uint8_t* bytes, std::size_t length);

  std::string LookupDomain(const IpKey& address) const override;

  std::size_t ExpireOutdated(std::chrono::steady_clock::time_point now);

  DnsObserverCounters Counters() const noexcept;

 private:
  struct Entry {
    std::string domain;
    std::chrono::steady_clock::time_point expires_at;
  };

  // Requires mutex_.
  void RecordLocked(const IpKey& address, const std::string& domain,
      std::uint32_t ttl_seconds, std::chrono::steady_clock::time_point now);

  DnsObserverConfiguration config_;

  mutable std::mutex mutex_;
  std::unordered_map<IpKey, Entry, IpKeyHash> entries_;
  DnsObserverCounters counters_;
};

}  // namespace fptn::tunnel
