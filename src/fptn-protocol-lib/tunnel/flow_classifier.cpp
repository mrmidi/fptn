/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/tunnel/flow_classifier.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace fptn::tunnel {

namespace {

constexpr std::size_t kMinIPv4Header = 20;
constexpr std::size_t kIPv6Header = 40;
constexpr std::uint8_t kProtoTcp = 6;
constexpr std::uint8_t kProtoUdp = 17;

std::uint16_t ReadBe16(const std::uint8_t* p) noexcept {
  return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

void HashCombine(std::size_t& seed, std::size_t value) noexcept {
  seed ^= value + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
}

std::size_t HashAddress(const IpKey& key) noexcept {
  // FNV-1a over the significant bytes only, so a v4 address does not hash the
  // twelve unused trailing zeroes.
  const std::size_t length = key.version == 4 ? 4u : 16u;
  std::size_t hash = 1469598103934665603ULL;
  for (std::size_t i = 0; i < length; ++i) {
    hash ^= key.bytes[i];
    hash *= 1099511628211ULL;
  }
  return hash;
}

}  // namespace

std::size_t IpKeyHash::operator()(const IpKey& key) const noexcept {
  return HashAddress(key);
}

std::size_t FiveTupleHash::operator()(const FiveTuple& tuple) const noexcept {
  std::size_t seed = HashAddress(tuple.destination);
  HashCombine(seed, HashAddress(tuple.source));
  HashCombine(seed, tuple.destination_port);
  HashCombine(seed, tuple.source_port);
  HashCombine(seed, static_cast<std::size_t>(tuple.protocol));
  return seed;
}

bool PeekFiveTuple(const std::uint8_t* bytes, std::uint32_t length,
    FiveTuple& out) noexcept {
  if (bytes == nullptr || length < kMinIPv4Header) {
    return false;
  }

  const std::uint8_t version = bytes[0] >> 4;
  std::size_t transport_offset = 0;
  std::uint8_t protocol = 0;

  if (version == 4) {
    const std::size_t header_length =
        static_cast<std::size_t>(bytes[0] & 0x0Fu) * 4u;
    if (header_length < kMinIPv4Header || length < header_length + 4u) {
      return false;
    }
    // Only the first fragment carries the transport header; a later fragment
    // has no ports to read, so it cannot be keyed.
    const std::uint16_t fragment_offset =
        static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(bytes[6] & 0x1Fu) << 8) | bytes[7]);
    if (fragment_offset != 0) {
      return false;
    }
    protocol = bytes[9];
    transport_offset = header_length;

    out.source.version = 4;
    out.destination.version = 4;
    out.source.bytes = {};
    out.destination.bytes = {};
    std::memcpy(out.source.bytes.data(), bytes + 12, 4);
    std::memcpy(out.destination.bytes.data(), bytes + 16, 4);
  } else if (version == 6) {
    if (length < kIPv6Header + 4u) {
      return false;
    }
    // Extension headers are not walked: they are rare on the paths we route,
    // and an unreadable tuple falls back to the safe (tunnelled) verdict.
    protocol = bytes[6];
    transport_offset = kIPv6Header;

    out.source.version = 6;
    out.destination.version = 6;
    std::memcpy(out.source.bytes.data(), bytes + 8, 16);
    std::memcpy(out.destination.bytes.data(), bytes + 24, 16);
  } else {
    return false;
  }

  if (protocol == kProtoTcp) {
    out.protocol = TransportProtocol::tcp;
  } else if (protocol == kProtoUdp) {
    out.protocol = TransportProtocol::udp;
  } else {
    return false;
  }

  if (length < transport_offset + 4u) {
    return false;
  }
  out.source_port = ReadBe16(bytes + transport_offset);
  out.destination_port = ReadBe16(bytes + transport_offset + 2);
  return true;
}

IpKey ToIpKey(const boost::asio::ip::address& address) noexcept {
  IpKey key;
  if (address.is_v4()) {
    key.version = 4;
    const auto raw = address.to_v4().to_bytes();
    std::memcpy(key.bytes.data(), raw.data(), raw.size());
  } else if (address.is_v6()) {
    key.version = 6;
    const auto raw = address.to_v6().to_bytes();
    std::memcpy(key.bytes.data(), raw.data(), raw.size());
  }
  return key;
}

boost::asio::ip::address FromIpKey(const IpKey& key) noexcept {
  if (key.version == 6) {
    boost::asio::ip::address_v6::bytes_type raw{};
    std::memcpy(raw.data(), key.bytes.data(), raw.size());
    return boost::asio::ip::address_v6(raw);
  }
  boost::asio::ip::address_v4::bytes_type raw{};
  std::memcpy(raw.data(), key.bytes.data(), raw.size());
  return boost::asio::ip::address_v4(raw);
}

FlowClassifier::FlowClassifier(ClassifierConfiguration config,
    const IRoutingPolicy& policy, const IDomainAttribution& attribution)
    : config_(config), policy_(policy), attribution_(attribution) {}

void FlowClassifier::SetServerEndpoint(
    const IpKey& address, std::uint16_t port) {
  std::lock_guard lock(mutex_);
  server_address_ = address;
  server_port_ = port;
}

void FlowClassifier::SetDirectResolvers(const std::vector<IpKey>& resolvers) {
  std::lock_guard lock(mutex_);
  direct_resolvers_ = resolvers;
}

void FlowClassifier::SetTunnelResolvers(const std::vector<IpKey>& resolvers) {
  std::lock_guard lock(mutex_);
  tunnel_resolvers_ = resolvers;
}

RouteAction FlowClassifier::Classify(const PacketLease& lease) noexcept {
  FiveTuple tuple;
  if (!PeekFiveTuple(lease.bytes, lease.length, tuple)) {
    std::lock_guard lock(mutex_);
    ++counters_.classified_packets;
    ++counters_.unclassifiable;
    return config_.unclassifiable_action;
  }

  const auto now = std::chrono::steady_clock::now();
  std::lock_guard lock(mutex_);
  ++counters_.classified_packets;

  if (++packets_since_sweep_ >= kSweepIntervalPackets) {
    packets_since_sweep_ = 0;
    // Inline so the table has a single owning thread pattern and needs no
    // timer; the cost is amortised across kSweepIntervalPackets packets.
    const auto timeout = config_.flow_idle_timeout;
    std::size_t removed = 0;
    for (auto it = flows_.begin(); it != flows_.end();) {
      if (now - it->second.last_seen > timeout) {
        it = flows_.erase(it);
        ++removed;
      } else {
        ++it;
      }
    }
    counters_.expired_flows += removed;
  }

  const auto found = flows_.find(tuple);
  if (found != flows_.end()) {
    found->second.last_seen = now;
    ++counters_.table_hits;
    return found->second.action;
  }

  const RouteAction action =
      DecideLocked(tuple, tuple.destination, tuple.destination_port);
  ++counters_.decisions;
  CountVerdictLocked(action);

  if (flows_.size() >= config_.max_flows) {
    // Bounded by construction: the verdict is still correct, it just costs a
    // policy lookup per packet until the table drains.
    ++counters_.table_full_events;
    return action;
  }
  flows_.emplace(tuple, Entry{action, now});
  counters_.active_flows = flows_.size();
  return action;
}

void FlowClassifier::CountVerdictLocked(RouteAction action) noexcept {
  switch (action) {
    case RouteAction::direct:
      ++counters_.direct_flows;
      break;
    case RouteAction::fptn_l4:
      ++counters_.fptn_flows;
      break;
    case RouteAction::reject:
      ++counters_.rejected_flows;
      break;
    case RouteAction::drop:
      ++counters_.dropped_flows;
      break;
  }
}

RouteAction FlowClassifier::DecideLocked(const FiveTuple& tuple,
    const IpKey& destination, std::uint16_t destination_port) {
  // Pinned rule 1: never tunnel the transport's own traffic.
  if (server_address_.has_value() && destination == *server_address_ &&
      (server_port_ == 0 || destination_port == server_port_)) {
    return RouteAction::direct;
  }
  // Pinned rule 2: the advertised resolvers live behind the tunnel.
  if (std::find(tunnel_resolvers_.begin(), tunnel_resolvers_.end(),
          destination) != tunnel_resolvers_.end()) {
    return RouteAction::fptn_l4;
  }
  // Pinned rule 3: a resolver the user chose is queried from here, not from
  // the server. Checked after rule 2 -- see SetDirectResolvers.
  if (std::find(direct_resolvers_.begin(), direct_resolvers_.end(),
          destination) != direct_resolvers_.end()) {
    return RouteAction::direct;
  }

  FlowMetadata metadata;
  metadata.protocol = tuple.protocol;
  // The addresses matter as much as the ports: a policy that matches on the
  // destination (the compiled geo tables) sees whatever is in here, so leaving
  // it default-constructed would have every flow asking about 0.0.0.0.
  metadata.destination.address = FromIpKey(destination);
  metadata.destination.port = destination_port;
  metadata.source.address = FromIpKey(tuple.source);
  metadata.source.port = tuple.source_port;

  const std::string domain = attribution_.LookupDomain(destination);
  return policy_.Decide(metadata, domain);
}

std::optional<RouteAction> FlowClassifier::LookupVerdict(
    const FlowMetadata& metadata) const noexcept {
  FiveTuple tuple;
  tuple.protocol = metadata.protocol;
  tuple.source = ToIpKey(metadata.source.address);
  tuple.destination = ToIpKey(metadata.destination.address);
  tuple.source_port = metadata.source.port;
  tuple.destination_port = metadata.destination.port;

  std::lock_guard lock(mutex_);
  const auto found = flows_.find(tuple);
  if (found == flows_.end()) {
    return std::nullopt;
  }
  return found->second.action;
}

std::size_t FlowClassifier::ExpireIdle(
    std::chrono::steady_clock::time_point now) noexcept {
  std::lock_guard lock(mutex_);
  const auto timeout = config_.flow_idle_timeout;
  std::size_t removed = 0;
  for (auto it = flows_.begin(); it != flows_.end();) {
    if (now - it->second.last_seen > timeout) {
      it = flows_.erase(it);
      ++removed;
    } else {
      ++it;
    }
  }
  counters_.expired_flows += removed;
  counters_.active_flows = flows_.size();
  return removed;
}

ClassifierCounters FlowClassifier::Counters() const noexcept {
  std::lock_guard lock(mutex_);
  ClassifierCounters out = counters_;
  out.active_flows = flows_.size();
  return out;
}

}  // namespace fptn::tunnel
