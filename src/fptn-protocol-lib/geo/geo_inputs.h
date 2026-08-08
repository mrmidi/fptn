/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "fptn-protocol-lib/geo/geo_compiler.h"
#include "fptn-protocol-lib/geo/geo_dat_parser.h"

namespace fptn::geo {

// Turns parsed .dat groups into compiler inputs by applying a verdict map.
//
// Separate from the parser because this is the only place a routing opinion
// exists: the parser knows a file format, the compiler knows a layout, and
// neither of them decides where traffic goes.

// The published geoip lists are two PROFILES, not two layers.
//
// Upstream ships DIRECT (the broad RU/BY set, used when the default is proxy
// and Russian destinations should stay off the server) and WHITELIST (a narrow,
// hand-curated set of Russian mobile-operator ranges, RU hosting and Yandex
// DNS). WHITELIST sits 98% inside DIRECT and is still not redundant, because
// the two are meant to be chosen between rather than unioned. Unioning them
// would quietly widen the direct set to the broad profile no matter which one
// the user picked.
enum class GeoIpProfile : std::uint8_t {
  // geoip:DIRECT decides what goes direct.
  standard = 0,
  // geoip:WHITELIST decides what goes direct; DIRECT is ignored.
  whitelist = 1,
};

// Bumped when the built-in mapping below changes. It reaches the artifact
// header as part of `verdict_map_id`, so a mapping change forces a recompile
// even when the source files are byte-identical.
inline constexpr std::uint32_t kVerdictMapVersion = 1;

struct GeoVerdictMap {
  GeoIpProfile ip_profile = GeoIpProfile::standard;

  // Verdict when nothing matches at all.
  GeoAction default_action = GeoAction::fptn;

  // Keys are upper-cased group names, matching what the parser produces.
  std::unordered_map<std::string, GeoAction> site;
  std::unordered_map<std::string, GeoAction> ip;

  // Applied to a group the map does not name. `none` skips the group; anything
  // else adopts it. Unlisted DOMAIN groups default to `fptn` rather than being
  // skipped, and that is deliberate: an explicit fptn rule for a name beats the
  // IP table, whereas skipping would let the IP table send it direct.
  GeoAction unmapped_site = GeoAction::fptn;
  GeoAction unmapped_ip = GeoAction::none;

  std::uint32_t id() const noexcept {
    return (kVerdictMapVersion << 8) | static_cast<std::uint32_t>(ip_profile);
  }
};

// The mapping documented by github.com/hydraponique/roscomvpn-routing.
//
// Do NOT infer these from group names -- several are counter-intuitive and
// inferring got 11 of 23 wrong: APPLE and MICROSOFT are direct so updates and
// push keep working, the game platforms are direct because they misbehave (and
// waste server traffic) through a proxy, TORRENT is blocked to spare the server
// and its host, and TWITCH-ADS is proxied rather than blocked because tunnelling
// it is what restores Source quality.
GeoVerdictMap DefaultVerdictMap(GeoIpProfile profile = GeoIpProfile::standard);

// What a regex was reduced to.
enum class GeoRegexOutcome : std::uint8_t {
  // "contains X and ends with Y" -- a GeoPairRule.
  pair = 0,
  // Matches only names with no dot in them, i.e. a local hostname. The whole
  // rule collapses into one header flag.
  bare_hostname = 1,
  // Not expressible. Reported, never silently dropped.
  unsupported = 2,
};

struct GeoRegexReduction {
  GeoRegexOutcome outcome = GeoRegexOutcome::unsupported;
  std::string contains;
  std::string suffix;
  // The pattern had structure between its wildcards that the pair rule cannot
  // express, so the reduction matches a superset of what the regex did. Safe
  // for routing, worth reporting.
  bool lossy = false;
};

// Reduces the regex shapes the published lists actually use, so the tunnel
// needs no regex engine. Exposed for tests, and because a pattern it cannot
// handle has to surface in the app rather than in a routing bug.
GeoRegexReduction ReduceRegex(std::string_view pattern);

// What the build did, so the app can show it rather than guess.
struct GeoInputsReport {
  std::uint32_t site_groups_used = 0;
  std::uint32_t site_groups_skipped = 0;
  std::uint32_t ip_groups_used = 0;
  std::uint32_t ip_groups_skipped = 0;
  std::uint32_t regexes_reduced = 0;
  std::uint32_t regexes_lossy = 0;
  // Patterns that could not be reduced, verbatim. Non-empty means some rule
  // upstream is not being enforced, and a person should see it.
  std::vector<std::string> unsupported_regexes;
  // Groups declared `inverse_match`, which is refused: inverting a set changes
  // where every unmatched address goes.
  std::vector<std::string> inverted_groups;
  bool bare_hostname_is_direct = false;
};

struct GeoInputsResult {
  GeoCompileInputs inputs;
  GeoInputsReport report;
};

GeoInputsResult BuildGeoInputs(const std::vector<GeoDatIpGroup>& ip_groups,
    const std::vector<GeoDatSiteGroup>& site_groups, const GeoVerdictMap& map);

}  // namespace fptn::geo
