/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <memory>
#include <string_view>

#include "fptn-protocol-lib/geo/geo_rule_set.h"
#include "fptn-protocol-lib/tunnel/routing_policy.h"

namespace fptn::geo {

// Routes a flow using a compiled geo rule set.
//
// Order is domain first, destination address second, artifact default third,
// and the constructor's fallback last.
//
// Domain wins because it is the more specific fact. A name resolves to an
// address that may be shared by a CDN with thousands of unrelated sites, and
// the IP tables are published as broad country-sized ranges -- so an address
// answers "roughly where is this" while a name answers "what is this". The
// address is the fallback for exactly the cases a name cannot cover: an
// IP-literal connection, or a resolution the tunnel never observed.
//
// This lives in geo/ rather than tunnel/ so the dependency runs one way: geo
// knows about routing verdicts, and the tunnel does not have to know a geo
// artifact exists in order to compile.
//
// Thread-safety: the mapped rule set is immutable after Open(), and this class
// adds no state, so concurrent Decide() calls are safe.
class GeoRoutingPolicy final : public fptn::tunnel::IRoutingPolicy {
 public:
  // `rules` may be null, and Decide() then answers `fallback` for everything.
  // That is the deliberate behaviour for a tunnel whose artifact failed to
  // load: it keeps running on one verdict rather than refusing to start.
  explicit GeoRoutingPolicy(std::shared_ptr<const GeoRuleSet> rules,
      fptn::tunnel::RouteAction fallback = fptn::tunnel::RouteAction::fptn_l4);

  fptn::tunnel::RouteAction Decide(const fptn::tunnel::FlowMetadata& flow,
      std::string_view domain) const override;

  bool has_rules() const noexcept;
  fptn::tunnel::RouteAction fallback() const noexcept { return fallback_; }

 private:
  // `none` when no interval or rule claims the address.
  GeoAction LookupAddress(const boost::asio::ip::address& address) const;

  std::shared_ptr<const GeoRuleSet> rules_;
  fptn::tunnel::RouteAction fallback_;
};

// Maps an on-disk verdict onto the engine's. `GeoAction::none` has no engine
// equivalent -- it means "no rule matched" -- so it yields `fallback`.
fptn::tunnel::RouteAction ToRouteAction(
    GeoAction action, fptn::tunnel::RouteAction fallback) noexcept;

}  // namespace fptn::geo
