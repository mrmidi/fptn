/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/geo/geo_compiler.h"

#include <openssl/sha.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <unordered_map>

namespace fptn::geo {

namespace {

constexpr std::size_t kActionCount = 5;
constexpr std::size_t kIpv4PrefixCount = 33;

std::string ToLowerAscii(std::string value) {
  for (char& c : value) {
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c - 'A' + 'a');
    }
  }
  return value;
}

void AppendPadding(std::vector<std::uint8_t>& out) {
  while ((out.size() % kSectionAlignment) != 0) {
    out.push_back(0);
  }
}

template <typename T>
void AppendPod(std::vector<std::uint8_t>& out, const T& value) {
  const auto* bytes = reinterpret_cast<const std::uint8_t*>(&value);
  out.insert(out.end(), bytes, bytes + sizeof(T));
}

std::uint8_t LabelCount(const std::string& value) {
  if (value.empty()) {
    return 0;
  }
  std::size_t count = 1;
  for (const char c : value) {
    if (c == '.') {
      ++count;
    }
  }
  return static_cast<std::uint8_t>(std::min<std::size_t>(count, 255));
}

// Precedence when two groups claim the same name with different verdicts.
//
// Higher wins, and the ordering is "the rule that asks for special handling
// beats the rule that says this is fine as-is". A name listed as blocked was
// listed deliberately; a name listed as needing the tunnel is usually there
// because it is geo-blocked, and answering `direct` would break it outright,
// whereas the reverse merely costs some server traffic.
//
// The alternative -- first rule wins -- makes routing depend on the order the
// groups happen to appear in the published file, which is not a decision
// anybody made.
std::uint8_t ActionRank(std::uint8_t action) {
  switch (static_cast<GeoAction>(action)) {
    case GeoAction::drop:
      return 4;
    case GeoAction::reject:
      return 3;
    case GeoAction::fptn:
      return 2;
    case GeoAction::direct:
      return 1;
    case GeoAction::none:
      break;
  }
  return 0;
}

// One boundary in the IPv4 sweep.
struct Event {
  std::uint64_t position = 0;  // 64-bit so end+1 of 255.255.255.255 fits
  bool opening = false;
  std::uint8_t prefix = 0;
  std::uint8_t action = 0;
};

// Flattens overlapping CIDRs into disjoint, gap-filled intervals with the
// longest-prefix winner already chosen.
//
// A sweep rather than the obvious "for each boundary, scan every rule": the
// published file has 42k ranges and ~30k boundaries, so the naive form is a
// billion comparisons. Active rules are counted per (prefix, action), which
// makes both the update and the winner query constant-time -- prefix is only
// ever 0..32.
std::vector<std::pair<std::uint32_t, std::uint8_t>> FlattenIpv4(
    const std::vector<GeoCidrInput>& cidrs, std::uint32_t& rules_in) {
  std::vector<Event> events;
  events.reserve(cidrs.size() * 2);

  for (const GeoCidrInput& cidr : cidrs) {
    if (cidr.is_ipv6 || cidr.prefix > 32 || cidr.action == GeoAction::none) {
      continue;
    }
    const std::uint32_t mask =
        (cidr.prefix == 0) ? 0u : (~0u << (32 - cidr.prefix));
    const auto base = static_cast<std::uint32_t>(cidr.low) & mask;
    const std::uint64_t start = base;
    const std::uint64_t end = base | static_cast<std::uint32_t>(~mask);
    events.push_back({start, true, cidr.prefix,
        static_cast<std::uint8_t>(cidr.action)});
    events.push_back({end + 1, false, cidr.prefix,
        static_cast<std::uint8_t>(cidr.action)});
    ++rules_in;
  }

  std::sort(events.begin(), events.end(),
      [](const Event& a, const Event& b) { return a.position < b.position; });

  std::array<std::array<std::int32_t, kActionCount>, kIpv4PrefixCount> active{};
  for (auto& row : active) {
    row.fill(0);
  }

  const auto winner = [&active]() -> std::uint8_t {
    for (std::size_t p = kIpv4PrefixCount; p-- > 0;) {
      for (std::size_t a = 0; a < kActionCount; ++a) {
        if (active[p][a] > 0) {
          return static_cast<std::uint8_t>(a);
        }
      }
    }
    return static_cast<std::uint8_t>(GeoAction::none);
  };

  // Always start at 0 so a lookup below the first covered range still finds a
  // predecessor, and the reader needs no special case for it.
  std::vector<std::pair<std::uint32_t, std::uint8_t>> intervals;
  intervals.emplace_back(0u, static_cast<std::uint8_t>(GeoAction::none));

  std::size_t i = 0;
  while (i < events.size()) {
    const std::uint64_t position = events[i].position;
    while (i < events.size() && events[i].position == position) {
      const Event& event = events[i];
      active[event.prefix][event.action] += event.opening ? 1 : -1;
      ++i;
    }
    if (position > 0xFFFFFFFFULL) {
      break;
    }
    const std::uint8_t action = winner();
    // Merging here is what takes 42k ranges to ~15k intervals: adjacent spans
    // that resolve to the same verdict are indistinguishable to a lookup.
    if (intervals.back().second != action) {
      intervals.emplace_back(static_cast<std::uint32_t>(position), action);
    }
  }

  return intervals;
}

}  // namespace

std::string GeoCompiler::ReverseLabels(const std::string& domain) {
  std::string out;
  out.reserve(domain.size());
  std::size_t end = domain.size();
  for (std::size_t i = domain.size(); i-- > 0;) {
    if (domain[i] == '.') {
      if (!out.empty()) {
        out.push_back('.');
      }
      out.append(domain, i + 1, end - i - 1);
      end = i;
    }
  }
  if (!out.empty()) {
    out.push_back('.');
  }
  out.append(domain, 0, end);
  return out;
}

GeoCompileResult GeoCompiler::Compile(
    const GeoCompileInputs& inputs, const GeoCompileOptions& options) {
  GeoCompileResult result;

  // ── IPv4 ────────────────────────────────────────────────────────────────
  const auto intervals = FlattenIpv4(inputs.cidrs, result.stats.ipv4_rules_in);
  result.stats.ipv4_intervals_out = static_cast<std::uint32_t>(intervals.size());

  // ── IPv6 ────────────────────────────────────────────────────────────────
  std::vector<GeoIpv6Rule> ipv6;
  for (const GeoCidrInput& cidr : inputs.cidrs) {
    if (!cidr.is_ipv6 || cidr.prefix > 128 || cidr.action == GeoAction::none) {
      continue;
    }
    GeoIpv6Rule rule = {};
    rule.high = cidr.high;
    rule.low = cidr.low;
    rule.prefix = cidr.prefix;
    rule.action = static_cast<std::uint8_t>(cidr.action);
    ipv6.push_back(rule);
  }
  result.stats.ipv6_rules = static_cast<std::uint32_t>(ipv6.size());

  // ── Domains ─────────────────────────────────────────────────────────────
  // Keyed by the reversed name, because that is what the reader binary-searches
  // and it can only find one entry per string. A suffix rule subsumes an exact
  // rule for the same name, so it wins; two different verdicts for the same
  // name are a contradiction in the source and are counted, not hidden.
  struct DomainEntry {
    GeoDomainKind kind = GeoDomainKind::suffix;
    std::uint8_t action = 0;
  };
  std::map<std::string, DomainEntry> domains;
  for (const GeoDomainInput& input : inputs.domains) {
    if (input.value.empty() || input.action == GeoAction::none) {
      continue;
    }
    ++result.stats.domain_rules_in;
    const std::string key = ReverseLabels(ToLowerAscii(input.value));
    const auto action = static_cast<std::uint8_t>(input.action);
    auto found = domains.find(key);
    if (found == domains.end()) {
      domains.emplace(key, DomainEntry{input.kind, action});
      continue;
    }
    if (found->second.action != action) {
      ++result.stats.domain_conflicts;
      if (ActionRank(action) > ActionRank(found->second.action)) {
        found->second.action = action;
      }
    }
    // Kind is resolved independently of the verdict: a suffix rule subsumes an
    // exact rule for the same name, whichever of them won the verdict.
    if (input.kind == GeoDomainKind::suffix) {
      found->second.kind = GeoDomainKind::suffix;
    }
  }
  result.stats.domain_rules_out = static_cast<std::uint32_t>(domains.size());

  std::uint8_t max_labels = 0;
  for (const auto& [key, entry] : domains) {
    max_labels = std::max(max_labels, LabelCount(key));
  }
  result.stats.max_domain_labels = max_labels;

  // ── Assemble ────────────────────────────────────────────────────────────
  GeoArtifactHeader header = {};
  std::memcpy(header.magic, kMagic, sizeof(kMagic));
  header.format_version = kFormatVersion;
  header.flags = options.bare_hostname_is_direct ? kFlagBareHostnameIsDirect : 0;
  std::memcpy(header.geoip_sha256, options.geoip_sha256.data(), kSha256Size);
  std::memcpy(
      header.geosite_sha256, options.geosite_sha256.data(), kSha256Size);
  header.built_at_unix = options.built_at_unix;
  header.verdict_map_id = options.verdict_map_id;
  header.default_action = static_cast<std::uint8_t>(options.default_action);
  header.max_domain_labels = max_labels;

  std::vector<std::uint8_t> body;

  const auto section_start = [&body]() {
    AppendPadding(body);
    return static_cast<std::uint32_t>(body.size() + sizeof(GeoArtifactHeader));
  };

  header.ipv4_offset = section_start();
  header.ipv4_count = static_cast<std::uint32_t>(intervals.size());
  for (const auto& [start, action] : intervals) {
    AppendPod(body, start);
  }
  for (const auto& [start, action] : intervals) {
    body.push_back(action);
  }

  header.ipv6_offset = section_start();
  header.ipv6_count = static_cast<std::uint32_t>(ipv6.size());
  for (const GeoIpv6Rule& rule : ipv6) {
    AppendPod(body, rule);
  }

  header.domain_offset = section_start();
  header.domain_count = static_cast<std::uint32_t>(domains.size());
  {
    std::vector<std::uint32_t> offsets;
    offsets.reserve(domains.size() + 1);
    std::string blob;
    for (const auto& [key, entry] : domains) {
      offsets.push_back(static_cast<std::uint32_t>(blob.size()));
      blob += key;
    }
    offsets.push_back(static_cast<std::uint32_t>(blob.size()));
    for (const std::uint32_t offset : offsets) {
      AppendPod(body, offset);
    }
    for (const auto& [key, entry] : domains) {
      body.push_back(entry.action);
    }
    for (const auto& [key, entry] : domains) {
      body.push_back(static_cast<std::uint8_t>(entry.kind));
    }
    header.domain_blob_offset = section_start();
    header.domain_blob_size = static_cast<std::uint32_t>(blob.size());
    body.insert(body.end(), blob.begin(), blob.end());
  }

  header.substring_offset = section_start();
  header.substring_count = static_cast<std::uint32_t>(inputs.substrings.size());
  {
    std::vector<std::uint32_t> offsets;
    offsets.reserve(inputs.substrings.size() + 1);
    std::string blob;
    for (const GeoSubstringInput& input : inputs.substrings) {
      offsets.push_back(static_cast<std::uint32_t>(blob.size()));
      blob += ToLowerAscii(input.value);
    }
    offsets.push_back(static_cast<std::uint32_t>(blob.size()));
    for (const std::uint32_t offset : offsets) {
      AppendPod(body, offset);
    }
    for (const GeoSubstringInput& input : inputs.substrings) {
      body.push_back(static_cast<std::uint8_t>(input.action));
    }
    header.substring_blob_offset = section_start();
    header.substring_blob_size = static_cast<std::uint32_t>(blob.size());
    body.insert(body.end(), blob.begin(), blob.end());
    result.stats.substring_rules = header.substring_count;
  }

  header.pair_offset = section_start();
  header.pair_count = static_cast<std::uint32_t>(inputs.pairs.size());
  {
    std::string blob;
    std::vector<GeoPairRule> rules;
    rules.reserve(inputs.pairs.size());
    for (const GeoPairInput& input : inputs.pairs) {
      GeoPairRule rule = {};
      const std::string contains = ToLowerAscii(input.contains);
      const std::string suffix = ToLowerAscii(input.suffix);
      rule.contains_offset = static_cast<std::uint32_t>(blob.size());
      rule.contains_size = static_cast<std::uint32_t>(contains.size());
      blob += contains;
      rule.suffix_offset = static_cast<std::uint32_t>(blob.size());
      rule.suffix_size = static_cast<std::uint32_t>(suffix.size());
      blob += suffix;
      rule.action = static_cast<std::uint8_t>(input.action);
      rules.push_back(rule);
    }
    for (const GeoPairRule& rule : rules) {
      AppendPod(body, rule);
    }
    header.pair_blob_offset = section_start();
    header.pair_blob_size = static_cast<std::uint32_t>(blob.size());
    body.insert(body.end(), blob.begin(), blob.end());
    result.stats.pair_rules = header.pair_count;
  }

  header.total_size =
      static_cast<std::uint32_t>(sizeof(GeoArtifactHeader) + body.size());

  // The digest covers the body only: it lives in the header, so it cannot
  // cover itself.
  ::SHA256(body.data(), body.size(), header.body_sha256);

  result.bytes.reserve(header.total_size);
  const auto* header_bytes = reinterpret_cast<const std::uint8_t*>(&header);
  result.bytes.insert(result.bytes.end(), header_bytes,
      header_bytes + sizeof(GeoArtifactHeader));
  result.bytes.insert(result.bytes.end(), body.begin(), body.end());
  result.ok = true;
  return result;
}

}  // namespace fptn::geo
