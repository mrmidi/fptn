/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/geo/geo_inputs.h"

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace fptn::geo {

namespace {

// Skips a quantifier following an atom: `*`, `+`, `?`, `{n}`, `{n,}`, `{n,m}`.
// Returns the position after it, or `i` when there is none.
std::size_t SkipQuantifier(std::string_view pattern, std::size_t i) {
  if (i >= pattern.size()) {
    return i;
  }
  const char c = pattern[i];
  if (c == '*' || c == '+' || c == '?') {
    ++i;
  } else if (c == '{') {
    const std::size_t close = pattern.find('}', i);
    if (close == std::string_view::npos) {
      return i;
    }
    i = close + 1;
  } else {
    return i;
  }
  // A lazy quantifier (`+?`) changes nothing about what the pattern matches.
  if (i < pattern.size() && pattern[i] == '?') {
    ++i;
  }
  return i;
}

// End of a `[...]` class, one past the `]`, or npos when unterminated.
std::size_t SkipCharClass(std::string_view pattern, std::size_t i) {
  // `i` points at '['. A ']' immediately after the opening (or after a
  // negation) is a literal member of the class, not its end.
  ++i;
  if (i < pattern.size() && pattern[i] == '^') {
    ++i;
  }
  if (i < pattern.size() && pattern[i] == ']') {
    ++i;
  }
  while (i < pattern.size()) {
    if (pattern[i] == '\\') {
      i += 2;
      continue;
    }
    if (pattern[i] == ']') {
      return i + 1;
    }
    ++i;
  }
  return std::string_view::npos;
}

bool IsAsciiAlnum(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
         (c >= 'A' && c <= 'Z');
}

std::string ToLowerAscii(std::string_view in) {
  std::string out(in);
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c - 'A' + 'a');
    }
  }
  return out;
}

// Whether `inner` lies entirely within `outer`. Both are CIDRs, so this is
// "at least as specific, and agreeing on the outer prefix" -- no need to
// materialise either range.
bool IsInside(const GeoPushRange& outer, bool is_ipv6, std::uint64_t high,
    std::uint64_t low, std::uint8_t prefix) {
  if (is_ipv6 != outer.is_ipv6 || prefix < outer.prefix) {
    return false;
  }
  if (!outer.is_ipv6) {
    const std::uint32_t mask =
        (outer.prefix == 0) ? 0u : (~0u << (32 - outer.prefix));
    return (static_cast<std::uint32_t>(low) & mask) ==
           (static_cast<std::uint32_t>(outer.low) & mask);
  }
  std::uint64_t high_mask = 0;
  std::uint64_t low_mask = 0;
  if (outer.prefix >= 64) {
    high_mask = ~0ULL;
    low_mask = (outer.prefix == 64) ? 0ULL : (~0ULL << (128 - outer.prefix));
  } else if (outer.prefix != 0) {
    high_mask = ~0ULL << (64 - outer.prefix);
  }
  return (high & high_mask) == (outer.high & high_mask) &&
         (low & low_mask) == (outer.low & low_mask);
}

bool IsInsideApplePush(bool is_ipv6, std::uint64_t high, std::uint64_t low,
    std::uint8_t prefix) {
  const std::vector<GeoPushRange>& ranges = ApplePushRanges();
  return std::any_of(ranges.begin(), ranges.end(),
      [&](const GeoPushRange& range) {
        return IsInside(range, is_ipv6, high, low, prefix);
      });
}

// True for the push name itself and anything under it, which is what a suffix
// rule for `push.apple.com` already covers.
bool IsUnderApplePushDomain(std::string_view value) {
  const std::string lowered = ToLowerAscii(value);
  if (lowered == kApplePushDomain) {
    return true;
  }
  return lowered.size() > kApplePushDomain.size() + 1 &&
         lowered.compare(lowered.size() - kApplePushDomain.size(),
             kApplePushDomain.size(), kApplePushDomain) == 0 &&
         lowered[lowered.size() - kApplePushDomain.size() - 1] == '.';
}

}  // namespace

const std::vector<GeoPushRange>& ApplePushRanges() {
  // Apple's published APNs ranges. Every one of them is also inside the
  // roscomvpn DIRECT set, which is precisely why the override has to exist:
  // matching them here and moving them to `fptn` is what keeps notifications
  // alive on a network that only permits what it has been told to.
  static const std::vector<GeoPushRange> ranges = {
      {false, 0, 0x11399000ULL, 22},   // 17.57.144.0/22
      {false, 0, 0x11BC1400ULL, 23},   // 17.188.20.0/23
      {false, 0, 0x11BC8000ULL, 18},   // 17.188.128.0/18
      {false, 0, 0x11F90000ULL, 16},   // 17.249.0.0/16
      {false, 0, 0x11FC0000ULL, 16},   // 17.252.0.0/16
      {true, 0x240303000A420000ULL, 0, 48},  // 2403:300:a42::/48
      {true, 0x240303000A510000ULL, 0, 48},  // 2403:300:a51::/48
      {true, 0x262001490A420000ULL, 0, 48},  // 2620:149:a42::/48
      {true, 0x262001490A440000ULL, 0, 48},  // 2620:149:a44::/48
      {true, 0x2A01B7400A420000ULL, 0, 48},  // 2a01:b740:a42::/48
  };
  return ranges;
}

GeoVerdictMap DefaultVerdictMap(
    GeoIpProfile profile, bool apple_push_via_fptn) {
  GeoVerdictMap map;
  map.ip_profile = profile;
  map.apple_push_via_fptn = apple_push_via_fptn;
  map.default_action = GeoAction::fptn;

  // RFC1918 and friends must never be tunnelled, under either profile.
  map.ip.emplace("PRIVATE", GeoAction::direct);
  map.ip.emplace(profile == GeoIpProfile::whitelist ? "WHITELIST" : "DIRECT",
      GeoAction::direct);

  map.site = {
      // VK video/music advertising, Windows telemetry, and the public
      // BitTorrent DHT -- the last blocked to spare the server and its host.
      {"CATEGORY-ADS", GeoAction::drop},
      {"WIN-SPY", GeoAction::drop},
      {"TORRENT", GeoAction::drop},

      {"WHITELIST", GeoAction::direct},
      {"CATEGORY-RU", GeoAction::direct},
      {"PRIVATE", GeoAction::direct},
      // Updates and push notifications have to keep working.
      {"APPLE", GeoAction::direct},
      {"MICROSOFT", GeoAction::direct},
      // Game platforms: proxying them wastes server traffic and breaks
      // matchmaking.
      {"STEAM", GeoAction::direct},
      {"EPICGAMES", GeoAction::direct},
      {"RIOT", GeoAction::direct},
      {"ESCAPEFROMTARKOV", GeoAction::direct},
      {"FACEIT", GeoAction::direct},
      {"TWITCH", GeoAction::direct},
      {"PINTEREST", GeoAction::direct},
  };

  // Everything else -- Google Play, YouTube, Telegram, GitHub, twitch-ads,
  // CATEGORY-GEOBLOCK-RU, and any group added upstream tomorrow -- tunnels.
  map.unmapped_site = GeoAction::fptn;
  map.unmapped_ip = GeoAction::none;
  return map;
}

GeoRegexReduction ReduceRegex(std::string_view pattern) {
  GeoRegexReduction result;
  if (pattern.empty()) {
    return result;
  }

  // Only end-anchored patterns are expressible: without `$` the regex matches
  // anywhere in the name, and "ends with" would be wrong.
  if (pattern.back() != '$') {
    return result;
  }
  pattern.remove_suffix(1);

  // `(^|\.)x` is "x at a label boundary". Reducing it to "contains x" widens
  // the match slightly, which is why the caller is told when a reduction is
  // approximate.
  if (pattern.starts_with("(^|\\.)")) {
    pattern.remove_prefix(6);
    result.lossy = true;
  } else if (pattern.starts_with('^')) {
    pattern.remove_prefix(1);
  } else {
    return result;
  }

  // A pattern with no dot anywhere -- neither literal nor metacharacter --
  // cannot match a name containing one, so it describes a dotless local
  // hostname and collapses into a header flag. It must be a SHAPE rather than
  // a literal: `^nas$` is also dotless, but it names one host and generalising
  // it to "every dotless name" would send far more traffic direct than the
  // rule asked for.
  if (pattern.find('.') == std::string_view::npos) {
    if (pattern.find_first_of("[]{}()|*+?\\") != std::string_view::npos) {
      result.outcome = GeoRegexOutcome::bare_hostname;
      result.lossy = false;
    }
    return result;
  }

  // Walk the pattern once, collecting runs of literal text separated by
  // wildcards.
  std::vector<std::string> literals(1);
  bool saw_wildcard = false;
  std::size_t i = 0;
  while (i < pattern.size()) {
    const char c = pattern[i];

    if (c == '\\') {
      if (i + 1 >= pattern.size()) {
        return result;
      }
      const char escaped = pattern[i + 1];
      i += 2;
      if (escaped == 'd' || escaped == 'D' || escaped == 'w' ||
          escaped == 'W' || escaped == 's' || escaped == 'S') {
        i = SkipQuantifier(pattern, i);
        literals.emplace_back();
        saw_wildcard = true;
      } else if (IsAsciiAlnum(escaped)) {
        // \b, \A, backreferences -- assertions and captures we do not model.
        return result;
      } else {
        literals.back().push_back(escaped);
      }
      continue;
    }

    if (c == '.') {
      ++i;
      i = SkipQuantifier(pattern, i);
      literals.emplace_back();
      saw_wildcard = true;
      continue;
    }

    if (c == '[') {
      const std::size_t end = SkipCharClass(pattern, i);
      if (end == std::string_view::npos) {
        return result;
      }
      i = SkipQuantifier(pattern, end);
      literals.emplace_back();
      saw_wildcard = true;
      continue;
    }

    // Alternation, grouping and quantifiers on literals would each need real
    // regex semantics. Refuse rather than approximate.
    if (c == '(' || c == ')' || c == '|' || c == '*' || c == '+' ||
        c == '?' || c == '{' || c == '^' || c == '$') {
      return result;
    }

    literals.back().push_back(c);
    ++i;
  }

  if (!saw_wildcard) {
    // A fully literal pattern is an exact-match rule wearing a regex costume;
    // the publisher should have used `full`. Report it rather than guessing.
    return result;
  }

  result.contains = literals.front();
  result.suffix = literals.back();
  if (result.contains.empty() || result.suffix.empty()) {
    return result;
  }
  // More than two runs means literal structure between wildcards was dropped.
  if (literals.size() > 2) {
    result.lossy = true;
  }
  result.outcome = GeoRegexOutcome::pair;
  return result;
}

GeoInputsResult BuildGeoInputs(const std::vector<GeoDatIpGroup>& ip_groups,
    const std::vector<GeoDatSiteGroup>& site_groups, const GeoVerdictMap& map,
    const std::vector<GeoDomainInput>& domain_overrides) {
  GeoInputsResult result;

  const auto verdict = [](const std::unordered_map<std::string, GeoAction>& in,
                           const std::string& name, GeoAction fallback) {
    const auto found = in.find(name);
    return found == in.end() ? fallback : found->second;
  };

  for (const GeoDatIpGroup& group : ip_groups) {
    const GeoAction action = verdict(map.ip, group.name, map.unmapped_ip);
    if (action == GeoAction::none) {
      ++result.report.ip_groups_skipped;
      continue;
    }
    // An inverted group means "everything except these", which flips the
    // verdict for every address the group does NOT list. Adopting its ranges
    // as-is would route the exact complement of what was intended.
    if (group.inverse_match) {
      result.report.inverted_groups.push_back(group.name);
      ++result.report.ip_groups_skipped;
      continue;
    }
    ++result.report.ip_groups_used;
    for (const GeoDatCidr& cidr : group.cidrs) {
      // Dropped rather than left to fight the override in the compiler: IPv4
      // flattening breaks a same-prefix tie by action order and IPv6 lookup by
      // array order, and the published ranges are prefix-for-prefix identical
      // to the override's. Removing the loser is the only way this wins that
      // does not depend on either of those internal orderings.
      if (map.apple_push_via_fptn &&
          IsInsideApplePush(cidr.is_ipv6, cidr.high, cidr.low, cidr.prefix)) {
        ++result.report.apple_push_rules_overridden;
        continue;
      }
      GeoCidrInput input;
      input.is_ipv6 = cidr.is_ipv6;
      input.high = cidr.high;
      input.low = cidr.low;
      input.prefix = cidr.prefix;
      input.action = action;
      result.inputs.cidrs.push_back(input);
    }
  }

  if (map.apple_push_via_fptn) {
    for (const GeoPushRange& range : ApplePushRanges()) {
      GeoCidrInput input;
      input.is_ipv6 = range.is_ipv6;
      input.high = range.high;
      input.low = range.low;
      input.prefix = range.prefix;
      input.action = GeoAction::fptn;
      result.inputs.cidrs.push_back(input);
    }
    // The name matters as much as the addresses. Address rules only apply once
    // a connection is being made, whereas the domain rule decides the flow the
    // moment the courier's name resolves -- and the published courier
    // addresses change without the name ever doing so.
    result.inputs.domains.push_back(GeoDomainInput{GeoDomainKind::suffix,
        std::string(kApplePushDomain), GeoAction::fptn});
  }

  for (const GeoDatSiteGroup& group : site_groups) {
    const GeoAction action = verdict(map.site, group.name, map.unmapped_site);
    if (action == GeoAction::none) {
      ++result.report.site_groups_skipped;
      continue;
    }
    ++result.report.site_groups_used;

    for (const GeoDatDomain& domain : group.domains) {
      // Suppressed rather than outvoted. The compiler resolves a name given
      // two verdicts by rank, which would land on `fptn` here anyway, but it
      // also counts that as a conflict -- and `domain_conflicts` is meant to
      // report the published lists disagreeing with themselves, not us
      // disagreeing with them on purpose.
      if (map.apple_push_via_fptn &&
          (domain.type == GeoDatDomainType::root_domain ||
              domain.type == GeoDatDomainType::full) &&
          IsUnderApplePushDomain(domain.value)) {
        ++result.report.apple_push_rules_overridden;
        continue;
      }
      switch (domain.type) {
        case GeoDatDomainType::root_domain:
          result.inputs.domains.push_back(
              GeoDomainInput{GeoDomainKind::suffix, domain.value, action});
          break;
        case GeoDatDomainType::full:
          result.inputs.domains.push_back(
              GeoDomainInput{GeoDomainKind::exact, domain.value, action});
          break;
        case GeoDatDomainType::plain:
          result.inputs.substrings.push_back(
              GeoSubstringInput{domain.value, action});
          break;
        case GeoDatDomainType::regex: {
          const GeoRegexReduction reduced = ReduceRegex(domain.value);
          switch (reduced.outcome) {
            case GeoRegexOutcome::pair:
              result.inputs.pairs.push_back(GeoPairInput{
                  reduced.contains, reduced.suffix, action});
              ++result.report.regexes_reduced;
              if (reduced.lossy) {
                ++result.report.regexes_lossy;
              }
              break;
            case GeoRegexOutcome::bare_hostname:
              // Only meaningful when the group it came from is direct; a
              // dotless name is a device on the local network.
              result.report.bare_hostname_is_direct =
                  result.report.bare_hostname_is_direct ||
                  action == GeoAction::direct;
              ++result.report.regexes_reduced;
              break;
            case GeoRegexOutcome::unsupported:
              result.report.unsupported_regexes.push_back(domain.value);
              break;
          }
          break;
        }
      }
    }
  }

  if (!domain_overrides.empty()) {
    AppendDomainOverrides(result, domain_overrides);
  }

  return result;
}

std::vector<GeoDomainInput> ParseDomainList(
    std::string_view text, GeoAction default_action) {
  std::vector<std::string> order;
  std::unordered_map<std::string, GeoDomainInput> dedup_map;

  auto trim = [](std::string_view s) -> std::string_view {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' ||
                             s.front() == '\r' || s.front() == '\n')) {
      s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' ||
                             s.back() == '\r' || s.back() == '\n')) {
      s.remove_suffix(1);
    }
    return s;
  };

  std::size_t start = 0;
  while (start < text.size()) {
    std::size_t end = text.find('\n', start);
    if (end == std::string_view::npos) {
      end = text.size();
    }
    std::string_view line = text.substr(start, end - start);
    start = end + 1;

    // Strip comments (# or //)
    const std::size_t hash_pos = line.find('#');
    if (hash_pos != std::string_view::npos) {
      line = line.substr(0, hash_pos);
    }
    const std::size_t slash_pos = line.find("//");
    if (slash_pos != std::string_view::npos) {
      line = line.substr(0, slash_pos);
    }

    line = trim(line);
    if (line.empty()) {
      continue;
    }

    // Lowercase the line so prefix checks (DOMAIN:, Full:, etc.) and domain names
    // are completely case-insensitive.
    std::string lowered = ToLowerAscii(std::string(line));
    std::string_view lview = lowered;
    lview = trim(lview);

    // Action prefix (e.g. direct:, fptn:, drop:, reject:)
    GeoAction action = default_action;
    if (lview.starts_with("direct:")) {
      action = GeoAction::direct;
      lview = trim(lview.substr(7));
    } else if (lview.starts_with("fptn:")) {
      action = GeoAction::fptn;
      lview = trim(lview.substr(5));
    } else if (lview.starts_with("drop:")) {
      action = GeoAction::drop;
      lview = trim(lview.substr(5));
    } else if (lview.starts_with("reject:")) {
      action = GeoAction::reject;
      lview = trim(lview.substr(7));
    }

    if (lview.empty()) {
      continue;
    }

    // Domain kind prefix (domain:, full:, *., .)
    GeoDomainKind kind = GeoDomainKind::suffix;
    if (lview.starts_with("domain:")) {
      kind = GeoDomainKind::suffix;
      lview = trim(lview.substr(7));
    } else if (lview.starts_with("full:")) {
      kind = GeoDomainKind::exact;
      lview = trim(lview.substr(5));
    } else if (lview.starts_with("*.")) {
      kind = GeoDomainKind::suffix;
      lview = trim(lview.substr(2));
    } else if (lview.starts_with(".")) {
      kind = GeoDomainKind::suffix;
      lview = trim(lview.substr(1));
    }

    lview = trim(lview);
    if (lview.empty()) {
      continue;
    }

    std::string canonical_domain(lview);
    auto found = dedup_map.find(canonical_domain);
    if (found == dedup_map.end()) {
      order.push_back(canonical_domain);
      dedup_map.emplace(canonical_domain,
          GeoDomainInput{kind, canonical_domain, action});
    } else {
      found->second.action = action;
      // Suffix subsumes exact
      if (kind == GeoDomainKind::suffix) {
        found->second.kind = GeoDomainKind::suffix;
      }
    }
  }

  std::vector<GeoDomainInput> result;
  result.reserve(order.size());
  for (const std::string& domain : order) {
    result.push_back(std::move(dedup_map[domain]));
  }
  return result;
}

void AppendDomainOverrides(GeoInputsResult& result,
    const std::vector<GeoDomainInput>& overrides) {
  if (overrides.empty()) {
    return;
  }

  auto is_same_or_subdomain = [](std::string_view domain, std::string_view parent) {
    if (domain == parent) {
      return true;
    }
    if (domain.size() > parent.size() + 1 &&
        domain.ends_with(parent) &&
        domain[domain.size() - parent.size() - 1] == '.') {
      return true;
    }
    return false;
  };

  for (const GeoDomainInput& override_item : overrides) {
    if (override_item.value.empty() || override_item.action == GeoAction::none) {
      continue;
    }
    const std::string override_key = ToLowerAscii(override_item.value);

    // If override is a suffix rule, clear conflicting base Geo DB subdomain rules
    // so the suffix rule governs them as intended (Git list > Geo DB).
    if (override_item.kind == GeoDomainKind::suffix) {
      auto it = result.inputs.domains.begin();
      while (it != result.inputs.domains.end()) {
        const std::string existing_key = ToLowerAscii(it->value);
        if (existing_key != override_key &&
            is_same_or_subdomain(existing_key, override_key)) {
          if (it->action != override_item.action) {
            it = result.inputs.domains.erase(it);
            ++result.report.domain_overrides_replaced;
            continue;
          }
        }
        ++it;
      }
    }

    // Look for exact match
    bool found = false;
    for (auto& d : result.inputs.domains) {
      if (ToLowerAscii(d.value) == override_key) {
        d.action = override_item.action;
        d.kind = override_item.kind;
        found = true;
        ++result.report.domain_overrides_replaced;
      }
    }
    if (!found) {
      result.inputs.domains.push_back(override_item);
      ++result.report.domain_overrides_added;
    }
  }
}

}  // namespace fptn::geo
