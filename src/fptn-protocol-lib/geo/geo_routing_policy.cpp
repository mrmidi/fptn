/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/geo/geo_routing_policy.h"

#include <array>
#include <utility>

#include <spdlog/spdlog.h>

namespace fptn::geo {

namespace {

using fptn::tunnel::RouteAction;

// An IPv4 address carried inside IPv6, ::ffff:a.b.c.d. The published lists put
// these ranges in the IPv4 table, so answering from the IPv6 table would miss
// every one of them.
bool IsIpv4Mapped(const std::array<unsigned char, 16>& bytes) {
  for (std::size_t i = 0; i < 10; ++i) {
    if (bytes[i] != 0) {
      return false;
    }
  }
  return bytes[10] == 0xFF && bytes[11] == 0xFF;
}

}  // namespace

RouteAction ToRouteAction(GeoAction action, RouteAction fallback) noexcept {
  switch (action) {
    case GeoAction::direct:
      return RouteAction::direct;
    case GeoAction::fptn:
      return RouteAction::fptn_l4;
    case GeoAction::reject:
      return RouteAction::reject;
    case GeoAction::drop:
      return RouteAction::drop;
    case GeoAction::none:
      break;
  }
  return fallback;
}

GeoRoutingPolicy::GeoRoutingPolicy(
    std::shared_ptr<const GeoRuleSet> rules, RouteAction fallback)
    : rules_(std::move(rules)), fallback_(fallback) {}

bool GeoRoutingPolicy::has_rules() const noexcept {
  return rules_ != nullptr && rules_->IsOpen();
}

GeoAction GeoRoutingPolicy::LookupAddress(
    const boost::asio::ip::address& address) const {
  if (address.is_v4()) {
    return rules_->LookupIpv4(address.to_v4().to_uint());
  }
  if (!address.is_v6()) {
    return GeoAction::none;
  }

  const std::array<unsigned char, 16> bytes = address.to_v6().to_bytes();
  if (IsIpv4Mapped(bytes)) {
    const std::uint32_t v4 = (static_cast<std::uint32_t>(bytes[12]) << 24) |
                             (static_cast<std::uint32_t>(bytes[13]) << 16) |
                             (static_cast<std::uint32_t>(bytes[14]) << 8) |
                             static_cast<std::uint32_t>(bytes[15]);
    return rules_->LookupIpv4(v4);
  }

  std::uint64_t high = 0;
  std::uint64_t low = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    high = (high << 8) | bytes[i];
    low = (low << 8) | bytes[i + 8];
  }
  return rules_->LookupIpv6(high, low);
}

RouteAction GeoRoutingPolicy::Decide(
    const fptn::tunnel::FlowMetadata& flow, std::string_view domain) const {
  if (!has_rules()) {
    return fallback_;
  }

  // Which table answered, for the log line. Debugging a routing complaint is
  // almost always "why did THIS go there", and the verdict alone does not say.
  const char* matched = "default";
  GeoAction action = GeoAction::none;

  if (!domain.empty()) {
    action = rules_->LookupDomain(domain);
    if (action != GeoAction::none) {
      matched = "name";
    }
  }
  if (action == GeoAction::none) {
    action = LookupAddress(flow.destination.address);
    if (action != GeoAction::none) {
      matched = "addr";
    }
  }
  if (action == GeoAction::none) {
    // The artifact's own default, which is what the verdict map was compiled
    // with; `fallback_` only covers an artifact that never loaded.
    action = rules_->default_action();
  }

  const RouteAction route = ToRouteAction(action, fallback_);

  // Debug rather than info: this is one line per flow, but it is also a record
  // of every destination the person visited. It compiles in and is filtered at
  // runtime, so it can be turned on in a shipped build without a new binary.
  SPDLOG_DEBUG("geo dest={} name={} -> {} [{}]",
      flow.destination.address.to_string(),
      domain.empty() ? std::string_view("-") : domain,
      fptn::tunnel::ToString(route), matched);

  return route;
}

}  // namespace fptn::geo
