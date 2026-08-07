/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "fptn-protocol-lib/tunnel/flow_types.h"

namespace fptn::tunnel {

class IRoutingPolicy {
 public:
  virtual ~IRoutingPolicy() = default;

  // `domain` is empty when the destination could not be attributed to a name
  // (an IP-literal connection, or a name we never observed being resolved).
  virtual RouteAction Decide(
      const FlowMetadata& flow, std::string_view domain) const = 0;
};

// Suffix-matched domain lists, one per non-default verdict, plus the verdict
// used when nothing matches.
//
// Matching is label-aware: a rule matches the domain itself or any subdomain
// of it, never a domain that merely ends with the same characters. So
// `mail.ru` matches `mail.ru` and `smtp.mail.ru`, but not `notmail.ru`.
//
// Lookup walks the domain's labels right to left against a hash map, so cost
// is O(labels) rather than O(rules) -- the geosite lists this will eventually
// be fed hold tens of thousands of entries.
class StaticDomainPolicy final : public IRoutingPolicy {
 public:
  explicit StaticDomainPolicy(RouteAction default_action = RouteAction::fptn_l4)
      : default_action_(default_action) {}

  // Accepts either a bare domain (`mail.ru`) or the `domain:mail.ru` form used
  // by the existing rule configuration. Ignores empty and malformed rules.
  // A later rule for the same domain replaces an earlier one.
  void AddRule(std::string_view rule, RouteAction action);

  // Convenience for loading a whole list at once.
  void AddRules(const std::vector<std::string>& rules, RouteAction action);

  RouteAction Decide(
      const FlowMetadata& flow, std::string_view domain) const override;

  RouteAction default_action() const noexcept { return default_action_; }
  std::size_t rule_count() const noexcept { return rules_.size(); }

 private:
  // Normalises to lower case, strips a `domain:` prefix, and trims a trailing
  // root dot. Returns an empty string when the rule cannot be used.
  static std::string NormalizeRule(std::string_view rule);

  RouteAction default_action_;
  std::unordered_map<std::string, RouteAction> rules_;
};

}  // namespace fptn::tunnel
