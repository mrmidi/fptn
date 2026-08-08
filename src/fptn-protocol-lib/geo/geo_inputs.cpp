/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/geo/geo_inputs.h"

#include <utility>

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

}  // namespace

GeoVerdictMap DefaultVerdictMap(GeoIpProfile profile) {
  GeoVerdictMap map;
  map.ip_profile = profile;
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
    const std::vector<GeoDatSiteGroup>& site_groups, const GeoVerdictMap& map) {
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
      GeoCidrInput input;
      input.is_ipv6 = cidr.is_ipv6;
      input.high = cidr.high;
      input.low = cidr.low;
      input.prefix = cidr.prefix;
      input.action = action;
      result.inputs.cidrs.push_back(input);
    }
  }

  for (const GeoDatSiteGroup& group : site_groups) {
    const GeoAction action = verdict(map.site, group.name, map.unmapped_site);
    if (action == GeoAction::none) {
      ++result.report.site_groups_skipped;
      continue;
    }
    ++result.report.site_groups_used;

    for (const GeoDatDomain& domain : group.domains) {
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

  return result;
}

}  // namespace fptn::geo
