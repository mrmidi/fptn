/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "fptn-protocol-lib/geo/geo_format.h"

namespace fptn::geo {

// Inputs are plain values rather than a parsed .dat, so the compiler can be
// tested exhaustively against hand-built cases and the file parser can change
// without touching it.

struct GeoCidrInput {
  bool is_ipv6 = false;
  // IPv4 uses `low` only, in host byte order.
  std::uint64_t high = 0;
  std::uint64_t low = 0;
  std::uint8_t prefix = 0;
  GeoAction action = GeoAction::none;
};

struct GeoDomainInput {
  GeoDomainKind kind = GeoDomainKind::suffix;
  std::string value;
  GeoAction action = GeoAction::none;
};

struct GeoSubstringInput {
  std::string value;
  GeoAction action = GeoAction::none;
};

struct GeoPairInput {
  std::string contains;
  std::string suffix;
  GeoAction action = GeoAction::none;
};

struct GeoCompileInputs {
  std::vector<GeoCidrInput> cidrs;
  std::vector<GeoDomainInput> domains;
  std::vector<GeoSubstringInput> substrings;
  std::vector<GeoPairInput> pairs;
};

struct GeoCompileOptions {
  GeoAction default_action = GeoAction::fptn;
  bool bare_hostname_is_direct = true;
  std::uint32_t verdict_map_id = 0;
  std::array<std::uint8_t, kSha256Size> geoip_sha256 = {};
  std::array<std::uint8_t, kSha256Size> geosite_sha256 = {};
  std::uint64_t built_at_unix = 0;
};

// What the compiler did, so the app can report it instead of guessing.
struct GeoCompileStats {
  std::uint32_t ipv4_rules_in = 0;
  std::uint32_t ipv4_intervals_out = 0;
  std::uint32_t ipv6_rules = 0;
  std::uint32_t domain_rules_in = 0;
  std::uint32_t domain_rules_out = 0;
  // Same name given two different verdicts. Resolved deterministically, but
  // worth surfacing: it means the source lists disagree with themselves.
  std::uint32_t domain_conflicts = 0;
  std::uint32_t substring_rules = 0;
  std::uint32_t pair_rules = 0;
  std::uint8_t max_domain_labels = 0;
};

struct GeoCompileResult {
  bool ok = false;
  std::string error;
  std::vector<std::uint8_t> bytes;
  GeoCompileStats stats;
};

// Compiles rules into the mappable artifact described by geo_format.h.
//
// The expensive, subtle work happens HERE rather than in the tunnel: the
// published ranges overlap heavily, so this flattens them into disjoint
// intervals with the winner already chosen. The tunnel then answers with one
// binary search and never re-derives precedence -- which is both faster and
// removes any chance of the two processes disagreeing about who wins.
class GeoCompiler {
 public:
  static GeoCompileResult Compile(
      const GeoCompileInputs& inputs, const GeoCompileOptions& options);

  // Reverses label order (`smtp.mail.ru` -> `ru.mail.smtp`). Exposed for
  // tests, and because the reader has to agree with it exactly.
  static std::string ReverseLabels(const std::string& domain);
};

}  // namespace fptn::geo
