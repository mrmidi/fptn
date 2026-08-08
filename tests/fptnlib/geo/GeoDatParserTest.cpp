/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "fptn-protocol-lib/geo/geo_dat_parser.h"
#include "fptn-protocol-lib/geo/geo_inputs.h"

namespace {

using fptn::geo::BuildGeoInputs;
using fptn::geo::DefaultVerdictMap;
using fptn::geo::GeoAction;
using fptn::geo::GeoDatDomainType;
using fptn::geo::GeoDatError;
using fptn::geo::GeoDatParser;
using fptn::geo::GeoDomainKind;
using fptn::geo::GeoInputsResult;
using fptn::geo::GeoIpProfile;
using fptn::geo::GeoRegexOutcome;
using fptn::geo::ReduceRegex;

using Bytes = std::vector<std::uint8_t>;

// ── A minimal protobuf writer, so the fixtures are built rather than checked
// in. Tests that construct their own input can cover shapes the published
// files do not contain -- truncation, bad prefixes, inverted groups.

void PutVarint(Bytes& out, std::uint64_t value) {
  do {
    std::uint8_t byte = value & 0x7F;
    value >>= 7;
    if (value != 0) {
      byte |= 0x80;
    }
    out.push_back(byte);
  } while (value != 0);
}

void PutTag(Bytes& out, int number, int wire_type) {
  PutVarint(out, (static_cast<std::uint64_t>(number) << 3) |
                     static_cast<std::uint64_t>(wire_type));
}

void PutVarintField(Bytes& out, int number, std::uint64_t value) {
  PutTag(out, number, 0);
  PutVarint(out, value);
}

void PutBytesField(Bytes& out, int number, const Bytes& payload) {
  PutTag(out, number, 2);
  PutVarint(out, payload.size());
  out.insert(out.end(), payload.begin(), payload.end());
}

void PutStringField(Bytes& out, int number, const std::string& value) {
  PutBytesField(out, number, Bytes(value.begin(), value.end()));
}

Bytes Domain(GeoDatDomainType type, const std::string& value) {
  Bytes out;
  PutVarintField(out, 1, static_cast<std::uint64_t>(type));
  PutStringField(out, 2, value);
  return out;
}

Bytes SiteGroup(const std::string& code, const std::vector<Bytes>& domains) {
  Bytes out;
  PutStringField(out, 1, code);
  for (const Bytes& domain : domains) {
    PutBytesField(out, 2, domain);
  }
  return out;
}

Bytes Cidr(const Bytes& ip, std::uint64_t prefix) {
  Bytes out;
  PutBytesField(out, 1, ip);
  PutVarintField(out, 2, prefix);
  return out;
}

Bytes IpGroup(const std::string& code, const std::vector<Bytes>& cidrs,
    bool inverse = false) {
  Bytes out;
  PutStringField(out, 1, code);
  for (const Bytes& cidr : cidrs) {
    PutBytesField(out, 2, cidr);
  }
  if (inverse) {
    PutVarintField(out, 3, 1);
  }
  return out;
}

Bytes Container(const std::vector<Bytes>& groups) {
  Bytes out;
  for (const Bytes& group : groups) {
    PutBytesField(out, 1, group);
  }
  return out;
}

Bytes Ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  return Bytes{a, b, c, d};
}

// ── geosite ─────────────────────────────────────────────────────────────────

TEST(GeoDatParserTest, ReadsGroupsAndEveryDomainType) {
  const Bytes file = Container({SiteGroup("apple",
      {Domain(GeoDatDomainType::root_domain, "apple.com"),
          Domain(GeoDatDomainType::full, "www.miwifi.com"),
          Domain(GeoDatDomainType::plain, "adobe"),
          Domain(GeoDatDomainType::regex, "^a.+\\.b\\.com$")})});

  const auto result = GeoDatParser::ParseGeoSite(file);

  ASSERT_TRUE(result.ok()) << fptn::geo::ToString(result.error);
  ASSERT_EQ(result.groups.size(), 1u);
  EXPECT_EQ(result.groups[0].name, "APPLE");
  ASSERT_EQ(result.groups[0].domains.size(), 4u);
  EXPECT_EQ(result.groups[0].domains[0].type, GeoDatDomainType::root_domain);
  EXPECT_EQ(result.groups[0].domains[1].type, GeoDatDomainType::full);
  EXPECT_EQ(result.groups[0].domains[2].type, GeoDatDomainType::plain);
  EXPECT_EQ(result.groups[0].domains[3].type, GeoDatDomainType::regex);
}

// The publisher fills both `country_code` and `code`; the latter is the real
// group name and the former is a legacy duplicate.
TEST(GeoDatParserTest, CodeFieldWinsOverCountryCode) {
  Bytes group;
  PutStringField(group, 1, "legacy");
  PutBytesField(
      group, 2, Domain(GeoDatDomainType::root_domain, "example.com"));
  PutStringField(group, 4, "category-ads");

  const auto result = GeoDatParser::ParseGeoSite(Container({group}));

  ASSERT_TRUE(result.ok());
  EXPECT_EQ(result.groups[0].name, "CATEGORY-ADS");
}

TEST(GeoDatParserTest, DomainValuesAreTrimmedAndLowerCased) {
  const Bytes file = Container({SiteGroup(
      "x", {Domain(GeoDatDomainType::root_domain, "  Apple.COM\n")})});

  const auto result = GeoDatParser::ParseGeoSite(file);

  ASSERT_TRUE(result.ok());
  EXPECT_EQ(result.groups[0].domains[0].value, "apple.com");
}

// An empty needle under `plain` would match every name there is.
TEST(GeoDatParserTest, ValuelessDomainRulesAreDropped) {
  const Bytes file = Container(
      {SiteGroup("x", {Domain(GeoDatDomainType::plain, "   "),
                          Domain(GeoDatDomainType::root_domain, "ok.com")})});

  const auto result = GeoDatParser::ParseGeoSite(file);

  ASSERT_TRUE(result.ok());
  ASSERT_EQ(result.groups[0].domains.size(), 1u);
  EXPECT_EQ(result.groups[0].domains[0].value, "ok.com");
}

// The publisher is free to add fields; a reader that rejects them is a reader
// that breaks on the next release.
TEST(GeoDatParserTest, UnknownFieldsAreSkipped) {
  Bytes group;
  PutStringField(group, 1, "x");
  PutVarintField(group, 9, 12345);
  PutBytesField(group, 2, Domain(GeoDatDomainType::root_domain, "ok.com"));
  PutStringField(group, 7, "something new");

  Bytes file;
  PutVarintField(file, 4, 1);
  PutBytesField(file, 1, group);

  const auto result = GeoDatParser::ParseGeoSite(file);

  ASSERT_TRUE(result.ok()) << fptn::geo::ToString(result.error);
  ASSERT_EQ(result.groups.size(), 1u);
  EXPECT_EQ(result.groups[0].domains.size(), 1u);
}

TEST(GeoDatParserTest, UnknownDomainTypeReadsAsPlain) {
  Bytes domain;
  PutVarintField(domain, 1, 99);
  PutStringField(domain, 2, "weird");

  Bytes group;
  PutStringField(group, 1, "x");
  PutBytesField(group, 2, domain);

  const auto result = GeoDatParser::ParseGeoSite(Container({group}));

  ASSERT_TRUE(result.ok());
  EXPECT_EQ(result.groups[0].domains[0].type, GeoDatDomainType::plain);
}

// ── geoip ───────────────────────────────────────────────────────────────────

TEST(GeoDatParserTest, ReadsIpv4Cidr) {
  const Bytes file =
      Container({IpGroup("direct", {Cidr(Ipv4(95, 213, 0, 0), 16)})});

  const auto result = GeoDatParser::ParseGeoIp(file);

  ASSERT_TRUE(result.ok()) << fptn::geo::ToString(result.error);
  ASSERT_EQ(result.groups.size(), 1u);
  EXPECT_EQ(result.groups[0].name, "DIRECT");
  ASSERT_EQ(result.groups[0].cidrs.size(), 1u);
  EXPECT_FALSE(result.groups[0].cidrs[0].is_ipv6);
  EXPECT_EQ(result.groups[0].cidrs[0].low, 0x5FD50000u);
  EXPECT_EQ(result.groups[0].cidrs[0].high, 0u);
  EXPECT_EQ(result.groups[0].cidrs[0].prefix, 16);
}

TEST(GeoDatParserTest, ReadsIpv6Cidr) {
  Bytes ip(16, 0);
  ip[0] = 0x2A;
  ip[1] = 0x02;
  ip[15] = 0x01;
  const Bytes file = Container({IpGroup("direct", {Cidr(ip, 32)})});

  const auto result = GeoDatParser::ParseGeoIp(file);

  ASSERT_TRUE(result.ok());
  ASSERT_EQ(result.groups[0].cidrs.size(), 1u);
  EXPECT_TRUE(result.groups[0].cidrs[0].is_ipv6);
  EXPECT_EQ(result.groups[0].cidrs[0].high, 0x2A02000000000000ull);
  EXPECT_EQ(result.groups[0].cidrs[0].low, 1ull);
  EXPECT_EQ(result.groups[0].cidrs[0].prefix, 32);
}

TEST(GeoDatParserTest, CarriesInverseMatchRatherThanIgnoringIt) {
  const Bytes file = Container(
      {IpGroup("weird", {Cidr(Ipv4(10, 0, 0, 0), 8)}, /*inverse=*/true)});

  const auto result = GeoDatParser::ParseGeoIp(file);

  ASSERT_TRUE(result.ok());
  EXPECT_TRUE(result.groups[0].inverse_match);
}

// ── refusals ────────────────────────────────────────────────────────────────

TEST(GeoDatParserTest, RefusesAnEmptyFile) {
  const auto result = GeoDatParser::ParseGeoSite(Bytes{});
  EXPECT_EQ(result.error, GeoDatError::empty);
}

// A precise answer instead of a stream of nonsense field numbers.
TEST(GeoDatParserTest, RefusesGzip) {
  const Bytes file = {0x1F, 0x8B, 0x08, 0x00, 0x00};
  const auto result = GeoDatParser::ParseGeoIp(file);
  EXPECT_EQ(result.error, GeoDatError::gzipped);
}

TEST(GeoDatParserTest, RefusesATruncatedFile) {
  Bytes file = Container({SiteGroup(
      "x", {Domain(GeoDatDomainType::root_domain, "example.com")})});
  file.resize(file.size() - 4);

  const auto result = GeoDatParser::ParseGeoSite(file);

  EXPECT_EQ(result.error, GeoDatError::truncated);
  EXPECT_TRUE(result.groups.empty());
}

// A length prefix far past the end of the buffer must not be trusted even for
// a moment: the read it would authorise is out of bounds.
TEST(GeoDatParserTest, RefusesAnOversizedLengthPrefix) {
  Bytes file;
  PutTag(file, 1, 2);
  PutVarint(file, 0xFFFFFFFFull);
  file.push_back(0x00);

  const auto result = GeoDatParser::ParseGeoSite(file);

  EXPECT_EQ(result.error, GeoDatError::truncated);
}

TEST(GeoDatParserTest, RefusesAnAddressThatIsNeither4Nor16Bytes) {
  const Bytes file =
      Container({IpGroup("direct", {Cidr(Bytes{1, 2, 3, 4, 5}, 24)})});

  const auto result = GeoDatParser::ParseGeoIp(file);

  EXPECT_EQ(result.error, GeoDatError::invalid_address_length);
}

TEST(GeoDatParserTest, RefusesAPrefixWiderThanItsFamily) {
  const Bytes file =
      Container({IpGroup("direct", {Cidr(Ipv4(10, 0, 0, 0), 33)})});

  const auto result = GeoDatParser::ParseGeoIp(file);

  EXPECT_EQ(result.error, GeoDatError::invalid_prefix);
}

TEST(GeoDatParserTest, RefusesAnUnnamedGroup) {
  const Bytes file = Container(
      {SiteGroup("", {Domain(GeoDatDomainType::root_domain, "example.com")})});

  const auto result = GeoDatParser::ParseGeoSite(file);

  EXPECT_EQ(result.error, GeoDatError::unnamed_group);
}

TEST(GeoDatParserTest, RefusesAFileWithNoGroups) {
  Bytes file;
  PutVarintField(file, 5, 1);

  const auto result = GeoDatParser::ParseGeoSite(file);

  EXPECT_EQ(result.error, GeoDatError::no_groups);
}

TEST(GeoDatParserTest, RefusesFieldNumberZero) {
  const Bytes file = {0x00, 0x00};
  const auto result = GeoDatParser::ParseGeoSite(file);
  EXPECT_EQ(result.error, GeoDatError::illegal_field_number);
}

TEST(GeoDatParserTest, RefusesAFieldWithTheWrongWireType) {
  Bytes file;
  // `entry` is a submessage; encoding it as a varint is not a file we wrote.
  PutVarintField(file, 1, 7);

  const auto result = GeoDatParser::ParseGeoSite(file);

  EXPECT_EQ(result.error, GeoDatError::unexpected_wire_type);
}

// ── the regex reducer ───────────────────────────────────────────────────────
//
// Every pattern below is one the published lists actually contain. If upstream
// adds a shape this cannot express, BuildGeoInputs reports it rather than
// dropping it, and these tests are where the new shape gets handled.

TEST(GeoRegexReduceTest, ReducesLabelBoundaryWildcardToContainsAndSuffix) {
  const auto reduced =
      ReduceRegex("(^|\\.)apiproxy-device-prod-nlb-.+\\.amazonaws\\.com$");

  EXPECT_EQ(reduced.outcome, GeoRegexOutcome::pair);
  EXPECT_EQ(reduced.contains, "apiproxy-device-prod-nlb-");
  EXPECT_EQ(reduced.suffix, ".amazonaws.com");
  // `(^|\.)` means "at a label boundary", which "contains" does not enforce.
  EXPECT_TRUE(reduced.lossy);
}

TEST(GeoRegexReduceTest, ReducesADottedPrefixBeforeTheWildcard) {
  const auto reduced =
      ReduceRegex("(^|\\.)dualstack\\.apiproxy-.+\\.amazonaws\\.com$");

  EXPECT_EQ(reduced.outcome, GeoRegexOutcome::pair);
  EXPECT_EQ(reduced.contains, "dualstack.apiproxy-");
  EXPECT_EQ(reduced.suffix, ".amazonaws.com");
}

TEST(GeoRegexReduceTest, ReducesACountedCharacterClass) {
  const auto reduced = ReduceRegex(
      "^github-production-release-asset-[0-9a-zA-Z]{6}\\.s3\\.amazonaws\\.com$");

  EXPECT_EQ(reduced.outcome, GeoRegexOutcome::pair);
  EXPECT_EQ(reduced.contains, "github-production-release-asset-");
  EXPECT_EQ(reduced.suffix, ".s3.amazonaws.com");
  EXPECT_FALSE(reduced.lossy);
}

// Two wildcards with a literal between them: the pair rule keeps the outer
// literals and loses the `-`, so it matches a superset. Safe for routing, and
// reported so it is a choice rather than an accident.
TEST(GeoRegexReduceTest, MultipleWildcardsReduceLosslyAndSaySo) {
  const auto reduced = ReduceRegex(
      "^chatgpt-async-webps-prod-\\S+-\\d+\\.webpubsub\\.azure\\.com$");

  EXPECT_EQ(reduced.outcome, GeoRegexOutcome::pair);
  EXPECT_EQ(reduced.contains, "chatgpt-async-webps-prod-");
  EXPECT_EQ(reduced.suffix, ".webpubsub.azure.com");
  EXPECT_TRUE(reduced.lossy);
}

TEST(GeoRegexReduceTest, RecognisesTheBareHostnameShape) {
  const auto reduced = ReduceRegex("^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$");

  EXPECT_EQ(reduced.outcome, GeoRegexOutcome::bare_hostname);
}

// Dotless, but it names one host. Generalising it to "every dotless name"
// would send far more direct than the rule asked for.
TEST(GeoRegexReduceTest, ADotlessLiteralIsNotTheBareHostnameShape) {
  EXPECT_EQ(ReduceRegex("^nas$").outcome, GeoRegexOutcome::unsupported);
}

TEST(GeoRegexReduceTest, RefusesAnUnanchoredPattern) {
  EXPECT_EQ(ReduceRegex("^foo.+\\.bar\\.com").outcome,
      GeoRegexOutcome::unsupported);
  EXPECT_EQ(ReduceRegex("foo.+\\.bar\\.com$").outcome,
      GeoRegexOutcome::unsupported);
}

TEST(GeoRegexReduceTest, RefusesAlternation) {
  EXPECT_EQ(ReduceRegex("^(a|b).+\\.example\\.com$").outcome,
      GeoRegexOutcome::unsupported);
}

TEST(GeoRegexReduceTest, RefusesAWildcardWithNothingLiteralAroundIt) {
  EXPECT_EQ(ReduceRegex("^.+\\.example\\.com$").outcome,
      GeoRegexOutcome::unsupported);
  EXPECT_EQ(ReduceRegex("^example\\.com.+$").outcome,
      GeoRegexOutcome::unsupported);
}

TEST(GeoRegexReduceTest, RefusesAnUnterminatedCharacterClass) {
  EXPECT_EQ(ReduceRegex("^a[0-9.+\\.example\\.com$").outcome,
      GeoRegexOutcome::unsupported);
}

TEST(GeoRegexReduceTest, RefusesEmptyAndTrivialInput) {
  EXPECT_EQ(ReduceRegex("").outcome, GeoRegexOutcome::unsupported);
  EXPECT_EQ(ReduceRegex("$").outcome, GeoRegexOutcome::unsupported);
}

// ── the verdict map ─────────────────────────────────────────────────────────

// Never infer these from group names. Inferring got 11 of 23 wrong; the
// authority is github.com/hydraponique/roscomvpn-routing.
TEST(GeoVerdictMapTest, TheCounterIntuitiveGroupsAreDirect) {
  const auto map = DefaultVerdictMap();

  for (const char* name : {"APPLE", "MICROSOFT", "STEAM", "EPICGAMES", "RIOT",
           "ESCAPEFROMTARKOV", "FACEIT", "TWITCH", "PINTEREST"}) {
    EXPECT_EQ(map.site.at(name), GeoAction::direct) << name;
  }
}

TEST(GeoVerdictMapTest, AdsTelemetryAndTorrentsAreDropped) {
  const auto map = DefaultVerdictMap();

  EXPECT_EQ(map.site.at("CATEGORY-ADS"), GeoAction::drop);
  EXPECT_EQ(map.site.at("WIN-SPY"), GeoAction::drop);
  EXPECT_EQ(map.site.at("TORRENT"), GeoAction::drop);
}

// Tunnelling twitch-ads is what restores Source quality, so it is proxied
// rather than blocked -- the opposite of what the name suggests.
TEST(GeoVerdictMapTest, UnlistedGroupsTunnel) {
  const auto map = DefaultVerdictMap();

  EXPECT_EQ(map.site.count("TWITCH-ADS"), 0u);
  EXPECT_EQ(map.site.count("YOUTUBE"), 0u);
  EXPECT_EQ(map.unmapped_site, GeoAction::fptn);
}

// The two geoip lists are profiles, not layers: WHITELIST sits 98% inside
// DIRECT, and unioning them would silently widen the direct set.
TEST(GeoVerdictMapTest, TheIpProfileSelectsExactlyOneDirectList) {
  const auto standard = DefaultVerdictMap(GeoIpProfile::standard);
  EXPECT_EQ(standard.ip.at("DIRECT"), GeoAction::direct);
  EXPECT_EQ(standard.ip.count("WHITELIST"), 0u);

  const auto whitelist = DefaultVerdictMap(GeoIpProfile::whitelist);
  EXPECT_EQ(whitelist.ip.at("WHITELIST"), GeoAction::direct);
  EXPECT_EQ(whitelist.ip.count("DIRECT"), 0u);

  // PRIVATE is RFC1918 and must never tunnel, under either profile.
  EXPECT_EQ(standard.ip.at("PRIVATE"), GeoAction::direct);
  EXPECT_EQ(whitelist.ip.at("PRIVATE"), GeoAction::direct);
}

// A changed profile must force a recompile even when the source files did not
// change, which is what verdict_map_id is for.
TEST(GeoVerdictMapTest, TheProfileChangesTheMapId) {
  EXPECT_NE(DefaultVerdictMap(GeoIpProfile::standard).id(),
      DefaultVerdictMap(GeoIpProfile::whitelist).id());
}

// ── building compiler inputs ────────────────────────────────────────────────

TEST(GeoInputsTest, DomainTypesLandInTheRightTables) {
  const std::vector<fptn::geo::GeoDatSiteGroup> groups = {
      {"APPLE",
          {{GeoDatDomainType::root_domain, "apple.com"},
              {GeoDatDomainType::full, "www.miwifi.com"},
              {GeoDatDomainType::plain, "adobe"},
              {GeoDatDomainType::regex, "^a-.+\\.b\\.com$"}}}};

  const GeoInputsResult result =
      BuildGeoInputs({}, groups, DefaultVerdictMap());

  ASSERT_EQ(result.inputs.domains.size(), 2u);
  EXPECT_EQ(result.inputs.domains[0].kind, GeoDomainKind::suffix);
  EXPECT_EQ(result.inputs.domains[1].kind, GeoDomainKind::exact);
  ASSERT_EQ(result.inputs.substrings.size(), 1u);
  EXPECT_EQ(result.inputs.substrings[0].value, "adobe");
  ASSERT_EQ(result.inputs.pairs.size(), 1u);
  EXPECT_EQ(result.inputs.pairs[0].contains, "a-");
  EXPECT_EQ(result.report.regexes_reduced, 1u);
  EXPECT_TRUE(result.report.unsupported_regexes.empty());
}

TEST(GeoInputsTest, EveryRuleInAGroupCarriesThatGroupsVerdict) {
  const std::vector<fptn::geo::GeoDatSiteGroup> groups = {
      {"TORRENT", {{GeoDatDomainType::root_domain, "rutracker.org"}}},
      {"APPLE", {{GeoDatDomainType::root_domain, "apple.com"}}},
      {"YOUTUBE", {{GeoDatDomainType::root_domain, "youtube.com"}}}};

  const GeoInputsResult result =
      BuildGeoInputs({}, groups, DefaultVerdictMap());

  ASSERT_EQ(result.inputs.domains.size(), 3u);
  EXPECT_EQ(result.inputs.domains[0].action, GeoAction::drop);
  EXPECT_EQ(result.inputs.domains[1].action, GeoAction::direct);
  // Unlisted, so it tunnels -- explicitly, which is what beats the IP table.
  EXPECT_EQ(result.inputs.domains[2].action, GeoAction::fptn);
  EXPECT_EQ(result.report.site_groups_used, 3u);
}

TEST(GeoInputsTest, TheUnselectedIpProfileIsSkippedEntirely) {
  const std::vector<fptn::geo::GeoDatIpGroup> groups = {
      {"DIRECT", false, {{false, 0, 0x5FD50000u, 16}}},
      {"WHITELIST", false, {{false, 0, 0x0A000000u, 8}}},
      {"PRIVATE", false, {{false, 0, 0xC0A80000u, 16}}}};

  const GeoInputsResult standard =
      BuildGeoInputs(groups, {}, DefaultVerdictMap(GeoIpProfile::standard));
  EXPECT_EQ(standard.inputs.cidrs.size(), 2u);
  EXPECT_EQ(standard.report.ip_groups_used, 2u);
  EXPECT_EQ(standard.report.ip_groups_skipped, 1u);

  const GeoInputsResult whitelist =
      BuildGeoInputs(groups, {}, DefaultVerdictMap(GeoIpProfile::whitelist));
  EXPECT_EQ(whitelist.inputs.cidrs.size(), 2u);
  EXPECT_EQ(whitelist.inputs.cidrs[0].low, 0x0A000000u);
}

// "Everything except these" flips the verdict for every address the group does
// not list. Adopting the ranges as-is would route the exact complement of what
// was intended.
TEST(GeoInputsTest, AnInvertedGroupIsRefusedAndReported) {
  const std::vector<fptn::geo::GeoDatIpGroup> groups = {
      {"DIRECT", true, {{false, 0, 0x5FD50000u, 16}}}};

  const GeoInputsResult result = BuildGeoInputs(groups, {}, DefaultVerdictMap());

  EXPECT_TRUE(result.inputs.cidrs.empty());
  ASSERT_EQ(result.report.inverted_groups.size(), 1u);
  EXPECT_EQ(result.report.inverted_groups[0], "DIRECT");
}

TEST(GeoInputsTest, AnUnreducibleRegexIsReportedVerbatim) {
  const std::vector<fptn::geo::GeoDatSiteGroup> groups = {
      {"GITHUB", {{GeoDatDomainType::regex, "^(alpha|beta)\\.example\\.com$"}}}};

  const GeoInputsResult result =
      BuildGeoInputs({}, groups, DefaultVerdictMap());

  EXPECT_TRUE(result.inputs.pairs.empty());
  ASSERT_EQ(result.report.unsupported_regexes.size(), 1u);
  EXPECT_EQ(
      result.report.unsupported_regexes[0], "^(alpha|beta)\\.example\\.com$");
}

// The bare-hostname flag is a routing decision, so it only turns on when the
// group that asked for it is itself direct.
TEST(GeoInputsTest, TheBareHostnameFlagFollowsItsGroupsVerdict) {
  const std::vector<fptn::geo::GeoDatSiteGroup> direct_group = {
      {"PRIVATE", {{GeoDatDomainType::regex, "^[a-z]([a-z0-9-]{0,61})?$"}}}};
  EXPECT_TRUE(BuildGeoInputs({}, direct_group, DefaultVerdictMap())
                  .report.bare_hostname_is_direct);

  const std::vector<fptn::geo::GeoDatSiteGroup> tunnelled_group = {
      {"YOUTUBE", {{GeoDatDomainType::regex, "^[a-z]([a-z0-9-]{0,61})?$"}}}};
  EXPECT_FALSE(BuildGeoInputs({}, tunnelled_group, DefaultVerdictMap())
                   .report.bare_hostname_is_direct);
}

// ── the published files ─────────────────────────────────────────────────────

// Opt-in, because the real lists are 500 KB and live in the app repo rather
// than here. Point FPTN_GEO_DAT_DIR at a directory holding geoip.dat and
// geosite.dat to run it:
//
//   FPTN_GEO_DAT_DIR=../FptnVPNTests/Fixtures ./GeoDatParserTest
//
// The counts are the ones measured when this was written. A mismatch is not a
// failure of the parser -- it means upstream published new lists, and the
// numbers below are the record of what they used to be.
TEST(GeoDatPublishedFilesTest, ParsesTheRealLists) {
  const char* dir = std::getenv("FPTN_GEO_DAT_DIR");
  if (dir == nullptr) {
    GTEST_SKIP() << "set FPTN_GEO_DAT_DIR to run against the published lists";
  }

  const auto read = [dir](const char* name) {
    const std::string path = std::string(dir) + "/" + name;
    std::vector<std::uint8_t> bytes;
    std::FILE* file = std::fopen(path.c_str(), "rb");
    if (file == nullptr) {
      return bytes;
    }
    std::uint8_t buffer[65536];
    std::size_t n = 0;
    while ((n = std::fread(buffer, 1, sizeof(buffer), file)) > 0) {
      bytes.insert(bytes.end(), buffer, buffer + n);
    }
    std::fclose(file);
    return bytes;
  };

  const auto geoip = read("geoip.dat");
  const auto geosite = read("geosite.dat");
  ASSERT_FALSE(geoip.empty()) << "geoip.dat not found under " << dir;
  ASSERT_FALSE(geosite.empty()) << "geosite.dat not found under " << dir;

  const auto ip = GeoDatParser::ParseGeoIp(geoip);
  ASSERT_TRUE(ip.ok()) << fptn::geo::ToString(ip.error) << " at "
                       << ip.error_offset;
  EXPECT_EQ(ip.groups.size(), 3u);
  std::size_t cidrs = 0;
  for (const auto& group : ip.groups) {
    cidrs += group.cidrs.size();
    EXPECT_FALSE(group.inverse_match) << group.name;
  }
  EXPECT_EQ(cidrs, 42383u);

  const auto site = GeoDatParser::ParseGeoSite(geosite);
  ASSERT_TRUE(site.ok()) << fptn::geo::ToString(site.error) << " at "
                         << site.error_offset;
  EXPECT_EQ(site.groups.size(), 23u);
  std::size_t domains = 0;
  for (const auto& group : site.groups) {
    domains += group.domains.size();
  }
  EXPECT_EQ(domains, 3107u);

  // Every regex in the published lists reduces, or the tunnel is not enforcing
  // a rule the publisher wrote.
  const GeoInputsResult built =
      BuildGeoInputs(ip.groups, site.groups, DefaultVerdictMap());
  EXPECT_TRUE(built.report.unsupported_regexes.empty())
      << built.report.unsupported_regexes.size() << " unreduced, first: "
      << (built.report.unsupported_regexes.empty()
                 ? std::string()
                 : built.report.unsupported_regexes.front());
  EXPECT_EQ(built.report.regexes_reduced, 7u);
  EXPECT_TRUE(built.report.bare_hostname_is_direct);
  EXPECT_TRUE(built.report.inverted_groups.empty());
}

}  // namespace
