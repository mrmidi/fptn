/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/tunnel/dns_observer.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>

#include <arpa/inet.h>

#include <spdlog/spdlog.h>

#include "common/network/ip_utils.h"

namespace fptn::tunnel {

namespace {

namespace net = fptn::common::network;

constexpr std::uint16_t kTypeA = 1;
constexpr std::uint16_t kTypeAAAA = 28;

std::uint32_t ReadBe32(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24) |
         (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) |
         static_cast<std::uint32_t>(p[3]);
}

// Returns the DNS payload of a UDP packet, or nullptr when the packet is not
// DNS. Mirrors IPPacket::DnsPtr but works on raw bytes so the observer can be
// tested without building an IPPacket.
const std::uint8_t* DnsPayload(
    const std::uint8_t* bytes, std::size_t length) noexcept {
  if (bytes == nullptr || length < net::detail::kMinIPv4) {
    return nullptr;
  }
  const std::uint8_t* end = bytes + length;
  const std::uint8_t version = bytes[0] >> 4;
  if (version == 4) {
    const std::size_t header_length =
        static_cast<std::size_t>(bytes[0] & 0x0Fu) * 4u;
    if (header_length < net::detail::kMinIPv4 || length < header_length ||
        net::detail::Ipv4Proto(bytes) != 17u) {
      return nullptr;
    }
    return net::detail::DnsPayloadPtr(bytes + header_length, end);
  }
  if (version == 6) {
    if (length < net::detail::kMinIPv6 || net::detail::Ipv6Next(bytes) != 17u) {
      return nullptr;
    }
    return net::detail::DnsPayloadPtr(bytes + net::detail::kMinIPv6, end);
  }
  return nullptr;
}

std::string FormatAddress(const IpKey& key) {
  char buffer[INET6_ADDRSTRLEN] = {};
  const int family = key.version == 6 ? AF_INET6 : AF_INET;
  if (::inet_ntop(family, key.bytes.data(), buffer, sizeof(buffer)) == nullptr) {
    return "?";
  }
  return buffer;
}

}  // namespace

DnsObserver::DnsObserver(DnsObserverConfiguration config)
    : config_(config) {}

void DnsObserver::Observe(
    const fptn::common::network::BatchIPPacketPtr& packets) {
  for (const auto& packet : packets) {
    if (!packet) {
      continue;
    }
    const auto& data = packet->Data();
    ObservePacket(data.data(), data.size());
  }
}

void DnsObserver::ObservePacket(
    const std::uint8_t* bytes, std::size_t length) {
  const std::uint8_t* dns = DnsPayload(bytes, length);
  if (dns == nullptr) {
    return;
  }
  const std::uint8_t* end = bytes + length;

  // Only responses carry answers; DnsAnswerStart checks the QR bit and skips
  // the question section, handling name compression.
  int ancount = 0;
  const std::uint8_t* cur = net::detail::DnsAnswerStart(dns, end, &ancount);
  if (cur == nullptr) {
    return;
  }

  // The question name is what a policy rule is written against. A CNAME chain
  // is deliberately collapsed onto it: a user asking to route `2ip.ru` direct
  // means the address it ultimately resolves to, whatever the alias.
  const std::uint8_t* question = dns + net::detail::kDnsHdr;
  const std::string domain =
      net::detail::ParseDnsName(dns, end, question);
  if (domain.empty()) {
    return;
  }

  const auto now = std::chrono::steady_clock::now();
  std::lock_guard lock(mutex_);
  ++counters_.responses_parsed;

  for (int answer = 0; answer < ancount && cur < end; ++answer) {
    // Skip this record's NAME (may be a compression pointer).
    for (int label = 0; label < 256 && cur < end; ++label) {
      const std::uint8_t len = *cur;
      if (len == 0u) {
        ++cur;
        break;
      }
      if ((len & 0xC0u) == 0xC0u) {
        cur += 2;
        break;
      }
      cur += 1 + len;
    }
    if (cur + 10 > end) {
      break;
    }
    const std::uint16_t rtype = net::ReadU16Be(cur);
    const std::uint32_t ttl = ReadBe32(cur + 4);
    const std::uint16_t rdlength = net::ReadU16Be(cur + 8);
    cur += 10;
    if (cur + rdlength > end) {
      break;
    }

    if (rtype == kTypeA && rdlength == 4u) {
      IpKey key;
      key.version = 4;
      std::memcpy(key.bytes.data(), cur, 4);
      RecordLocked(key, domain, ttl, now);
    } else if (rtype == kTypeAAAA && rdlength == 16u) {
      IpKey key;
      key.version = 6;
      std::memcpy(key.bytes.data(), cur, 16);
      RecordLocked(key, domain, ttl, now);
    }
    cur += rdlength;
  }
}

void DnsObserver::RecordLocked(const IpKey& address, const std::string& domain,
    std::uint32_t ttl_seconds,
    std::chrono::steady_clock::time_point now) {
  const auto clamped = std::clamp(std::chrono::seconds(ttl_seconds),
      config_.min_ttl, config_.max_ttl);

  if (entries_.size() >= config_.max_entries &&
      !entries_.contains(address)) {
    // Drop everything already expired first; only evict live entries if that
    // was not enough.
    for (auto it = entries_.begin(); it != entries_.end();) {
      if (it->second.expires_at <= now) {
        it = entries_.erase(it);
        ++counters_.mappings_expired;
      } else {
        ++it;
      }
    }
    while (entries_.size() >= config_.max_entries) {
      auto oldest = std::min_element(entries_.begin(), entries_.end(),
          [](const auto& a, const auto& b) {
            return a.second.expires_at < b.second.expires_at;
          });
      if (oldest == entries_.end()) {
        break;
      }
      entries_.erase(oldest);
      ++counters_.evictions;
    }
  }

  // Last writer wins: one address can serve several names, and the most
  // recently resolved one is the best guess for the connection about to open.
  const auto existing = entries_.find(address);
  const bool changed =
      existing == entries_.end() || existing->second.domain != domain;
  entries_[address] = Entry{domain, now + clamped};
  ++counters_.mappings_recorded;
  if (changed) {
    // Only when the mapping is new or the name changed: a busy resolver
    // re-confirms the same answer constantly and would drown the log.
    SPDLOG_DEBUG("dns {} -> {} (ttl {}s)", domain, FormatAddress(address),
        static_cast<long long>(clamped.count()));
  }
}

std::string DnsObserver::LookupDomain(const IpKey& address) const {
  const auto now = std::chrono::steady_clock::now();
  std::lock_guard lock(mutex_);
  const auto found = entries_.find(address);
  if (found == entries_.end()) {
    return {};
  }
  if (found->second.expires_at <= now) {
    return {};
  }
  return found->second.domain;
}

std::size_t DnsObserver::ExpireOutdated(
    std::chrono::steady_clock::time_point now) {
  std::lock_guard lock(mutex_);
  std::size_t removed = 0;
  for (auto it = entries_.begin(); it != entries_.end();) {
    if (it->second.expires_at <= now) {
      it = entries_.erase(it);
      ++removed;
    } else {
      ++it;
    }
  }
  counters_.mappings_expired += removed;
  return removed;
}

DnsObserverCounters DnsObserver::Counters() const noexcept {
  std::lock_guard lock(mutex_);
  DnsObserverCounters out = counters_;
  out.entries = entries_.size();
  return out;
}

}  // namespace fptn::tunnel
