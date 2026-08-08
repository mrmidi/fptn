/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <gtest/gtest.h>
#include <unistd.h>

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "fptn-protocol-lib/geo/geo_compiler.h"
#include "fptn-protocol-lib/geo/geo_dat_parser.h"
#include "fptn-protocol-lib/geo/geo_inputs.h"
#include "fptn-protocol-lib/geo/geo_routing_policy.h"
#include "fptn-protocol-lib/tunnel/flow_classifier.h"

namespace {

using fptn::geo::GeoAction;
using fptn::geo::GeoCidrInput;
using fptn::geo::GeoCompileInputs;
using fptn::geo::GeoCompiler;
using fptn::geo::GeoCompileOptions;
using fptn::geo::GeoDomainInput;
using fptn::geo::GeoDomainKind;
using fptn::geo::GeoRoutingPolicy;
using fptn::geo::GeoRuleSet;
using fptn::geo::GeoSubstringInput;
using fptn::tunnel::FlowMetadata;
using fptn::tunnel::RouteAction;

std::uint32_t Ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c,
    std::uint8_t d) {
  return (static_cast<std::uint32_t>(a) << 24) |
         (static_cast<std::uint32_t>(b) << 16) |
         (static_cast<std::uint32_t>(c) << 8) | d;
}

GeoCidrInput V4(std::uint32_t base, std::uint8_t prefix, GeoAction action) {
  GeoCidrInput cidr;
  cidr.low = base;
  cidr.prefix = prefix;
  cidr.action = action;
  return cidr;
}

GeoCidrInput V6(std::uint64_t high, std::uint64_t low, std::uint8_t prefix,
    GeoAction action) {
  GeoCidrInput cidr;
  cidr.is_ipv6 = true;
  cidr.high = high;
  cidr.low = low;
  cidr.prefix = prefix;
  cidr.action = action;
  return cidr;
}

// Writes the artifact somewhere it can be mapped, and removes it on
// destruction.
class TempArtifact {
 public:
  explicit TempArtifact(const std::vector<std::uint8_t>& bytes) {
    char name[] = "/tmp/fptn-geo-policy-XXXXXX";
    const int fd = ::mkstemp(name);
    path_ = name;
    if (fd < 0) {
      return;
    }
    std::size_t written = 0;
    while (written < bytes.size()) {
      const ssize_t n =
          ::write(fd, bytes.data() + written, bytes.size() - written);
      if (n <= 0) {
        break;
      }
      written += static_cast<std::size_t>(n);
    }
    ::close(fd);
  }
  ~TempArtifact() { std::remove(path_.c_str()); }

  TempArtifact(const TempArtifact&) = delete;
  TempArtifact& operator=(const TempArtifact&) = delete;

  const std::string& path() const { return path_; }

 private:
  std::string path_;
};

// Compiles, writes and maps in one step, keeping the file alive as long as the
// rule set that maps it.
class MappedRules {
 public:
  MappedRules(const GeoCompileInputs& inputs, GeoAction default_action) {
    GeoCompileOptions options;
    options.default_action = default_action;
    const auto compiled = GeoCompiler::Compile(inputs, options);
    file_ = std::make_unique<TempArtifact>(compiled.bytes);
    rules_ = std::make_shared<GeoRuleSet>();
    error_ = rules_->Open(file_->path());
  }

  const std::shared_ptr<GeoRuleSet>& rules() const { return rules_; }
  fptn::geo::GeoLoadError error() const { return error_; }

 private:
  std::unique_ptr<TempArtifact> file_;
  std::shared_ptr<GeoRuleSet> rules_;
  fptn::geo::GeoLoadError error_ = fptn::geo::GeoLoadError::none;
};

FlowMetadata FlowTo(const std::string& address) {
  FlowMetadata flow;
  flow.id = 1;
  flow.protocol = fptn::tunnel::TransportProtocol::tcp;
  flow.destination.address = boost::asio::ip::make_address(address);
  flow.destination.port = 443;
  return flow;
}

// An artifact covering both a name and an address, with different verdicts, so
// every ordering test can tell which one answered.
GeoCompileInputs SampleInputs() {
  GeoCompileInputs inputs;
  inputs.domains.push_back(
      GeoDomainInput{GeoDomainKind::suffix, "youtube.com", GeoAction::fptn});
  inputs.domains.push_back(
      GeoDomainInput{GeoDomainKind::suffix, "mail.ru", GeoAction::direct});
  inputs.domains.push_back(
      GeoDomainInput{GeoDomainKind::suffix, "ads.example", GeoAction::drop});
  inputs.cidrs.push_back(V4(Ipv4(95, 213, 0, 0), 16, GeoAction::direct));
  inputs.cidrs.push_back(V4(Ipv4(10, 0, 0, 0), 8, GeoAction::direct));
  return inputs;
}

// ── the fallback path ───────────────────────────────────────────────────────

// The artifact failing to load must not stop the tunnel; it falls back to one
// verdict and keeps routing.
TEST(GeoRoutingPolicyTest, ANullRuleSetAnswersTheFallbackForEverything) {
  const GeoRoutingPolicy policy(nullptr, RouteAction::fptn_l4);

  EXPECT_FALSE(policy.has_rules());
  EXPECT_EQ(policy.Decide(FlowTo("95.213.1.1"), "mail.ru"),
      RouteAction::fptn_l4);
  EXPECT_EQ(policy.Decide(FlowTo("1.1.1.1"), ""), RouteAction::fptn_l4);
}

TEST(GeoRoutingPolicyTest, AnUnopenedRuleSetAnswersTheFallback) {
  const GeoRoutingPolicy policy(
      std::make_shared<GeoRuleSet>(), RouteAction::direct);

  EXPECT_FALSE(policy.has_rules());
  EXPECT_EQ(policy.Decide(FlowTo("95.213.1.1"), "mail.ru"),
      RouteAction::direct);
}

// ── ordering ────────────────────────────────────────────────────────────────

// The whole point of the ordering. The address says "Russian hosting, go
// direct"; the name says "geo-blocked, tunnel it". The name is the more
// specific fact and has to win, or every site behind an RU-hosted CDN takes
// the address's verdict.
TEST(GeoRoutingPolicyTest, TheNameWinsOverTheAddress) {
  const MappedRules mapped(SampleInputs(), GeoAction::fptn);
  ASSERT_EQ(mapped.error(), fptn::geo::GeoLoadError::none);
  const GeoRoutingPolicy policy(mapped.rules(), RouteAction::fptn_l4);

  EXPECT_EQ(policy.Decide(FlowTo("95.213.1.1"), "youtube.com"),
      RouteAction::fptn_l4);
  // ...and the reverse pairing, so this is not just the default in disguise.
  EXPECT_EQ(policy.Decide(FlowTo("8.8.8.8"), "mail.ru"), RouteAction::direct);
}

TEST(GeoRoutingPolicyTest, TheAddressAnswersWhenTheNameIsUnknown) {
  const MappedRules mapped(SampleInputs(), GeoAction::fptn);
  const GeoRoutingPolicy policy(mapped.rules(), RouteAction::fptn_l4);

  EXPECT_EQ(policy.Decide(FlowTo("95.213.1.1"), "unlisted.example"),
      RouteAction::direct);
}

// An IP-literal connection has no name to attribute, which is exactly the case
// the address table exists for.
TEST(GeoRoutingPolicyTest, TheAddressAnswersWhenThereIsNoName) {
  const MappedRules mapped(SampleInputs(), GeoAction::fptn);
  const GeoRoutingPolicy policy(mapped.rules(), RouteAction::fptn_l4);

  EXPECT_EQ(policy.Decide(FlowTo("95.213.1.1"), ""), RouteAction::direct);
  EXPECT_EQ(policy.Decide(FlowTo("10.1.2.3"), ""), RouteAction::direct);
}

TEST(GeoRoutingPolicyTest, TheArtifactDefaultAnswersWhenNothingMatches) {
  const MappedRules mapped(SampleInputs(), GeoAction::fptn);
  const GeoRoutingPolicy policy(mapped.rules(), RouteAction::direct);

  // The fallback is `direct` here, so answering fptn proves the verdict came
  // from the artifact and not from the constructor.
  EXPECT_EQ(policy.Decide(FlowTo("8.8.8.8"), "unlisted.example"),
      RouteAction::fptn_l4);
}

// A `none` default is a rule set that declines to answer, which is the one
// case the constructor's fallback is for.
TEST(GeoRoutingPolicyTest, TheFallbackCoversAnArtifactWithNoDefault) {
  const MappedRules mapped(SampleInputs(), GeoAction::none);
  const GeoRoutingPolicy policy(mapped.rules(), RouteAction::reject);

  EXPECT_EQ(policy.Decide(FlowTo("8.8.8.8"), "unlisted.example"),
      RouteAction::reject);
}

// ── verdict mapping ─────────────────────────────────────────────────────────

TEST(GeoRoutingPolicyTest, EveryVerdictReachesTheEngineIntact) {
  GeoCompileInputs inputs;
  inputs.domains.push_back(
      GeoDomainInput{GeoDomainKind::suffix, "direct.example", GeoAction::direct});
  inputs.domains.push_back(
      GeoDomainInput{GeoDomainKind::suffix, "fptn.example", GeoAction::fptn});
  inputs.domains.push_back(GeoDomainInput{
      GeoDomainKind::suffix, "reject.example", GeoAction::reject});
  inputs.domains.push_back(
      GeoDomainInput{GeoDomainKind::suffix, "drop.example", GeoAction::drop});

  const MappedRules mapped(inputs, GeoAction::fptn);
  const GeoRoutingPolicy policy(mapped.rules(), RouteAction::fptn_l4);

  EXPECT_EQ(policy.Decide(FlowTo("1.1.1.1"), "direct.example"),
      RouteAction::direct);
  EXPECT_EQ(
      policy.Decide(FlowTo("1.1.1.1"), "fptn.example"), RouteAction::fptn_l4);
  EXPECT_EQ(
      policy.Decide(FlowTo("1.1.1.1"), "reject.example"), RouteAction::reject);
  EXPECT_EQ(
      policy.Decide(FlowTo("1.1.1.1"), "drop.example"), RouteAction::drop);
}

// ── address families ────────────────────────────────────────────────────────

// The published lists put these ranges in the IPv4 table, so an address that
// arrives as ::ffff:a.b.c.d has to be answered from there or every one of them
// misses.
TEST(GeoRoutingPolicyTest, AnIpv4MappedAddressUsesTheIpv4Table) {
  const MappedRules mapped(SampleInputs(), GeoAction::fptn);
  const GeoRoutingPolicy policy(mapped.rules(), RouteAction::fptn_l4);

  EXPECT_EQ(policy.Decide(FlowTo("::ffff:95.213.1.1"), ""),
      RouteAction::direct);
  EXPECT_EQ(policy.Decide(FlowTo("::ffff:8.8.8.8"), ""), RouteAction::fptn_l4);
}

TEST(GeoRoutingPolicyTest, Ipv6AddressesAreMatchedOnTheirOwnTable) {
  GeoCompileInputs inputs;
  inputs.cidrs.push_back(
      V6(0x2A0206B800000000ull, 0, 32, GeoAction::direct));

  const MappedRules mapped(inputs, GeoAction::fptn);
  const GeoRoutingPolicy policy(mapped.rules(), RouteAction::fptn_l4);

  EXPECT_EQ(policy.Decide(FlowTo("2a02:6b8::1"), ""), RouteAction::direct);
  EXPECT_EQ(policy.Decide(FlowTo("2606:4700::1"), ""), RouteAction::fptn_l4);
}

// ── the domain tables the engine could not express before ───────────────────

TEST(GeoRoutingPolicyTest, SubdomainsAndSubstringRulesBothReachThePolicy) {
  GeoCompileInputs inputs;
  inputs.domains.push_back(
      GeoDomainInput{GeoDomainKind::suffix, "mail.ru", GeoAction::direct});
  inputs.substrings.push_back(GeoSubstringInput{"adobe", GeoAction::fptn});

  const MappedRules mapped(inputs, GeoAction::reject);
  const GeoRoutingPolicy policy(mapped.rules(), RouteAction::drop);

  EXPECT_EQ(policy.Decide(FlowTo("1.1.1.1"), "smtp.mail.ru"),
      RouteAction::direct);
  // Label-aware, so a name that merely ends with the same characters misses.
  EXPECT_EQ(
      policy.Decide(FlowTo("1.1.1.1"), "notmail.ru"), RouteAction::reject);
  EXPECT_EQ(policy.Decide(FlowTo("1.1.1.1"), "cdn.adobe.io"),
      RouteAction::fptn_l4);
}

// ── the classifier hands over what the policy needs ─────────────────────────

// FlowMetadata used to reach the policy with only its ports filled in, so an
// address-matching policy saw 0.0.0.0 for every flow. Round-trip the key to
// prove the address survives.
TEST(GeoRoutingPolicyTest, TheClassifierKeyRoundTripsToAnAddress) {
  for (const char* literal :
      {"95.213.1.1", "10.0.0.1", "2a02:6b8::1", "::ffff:8.8.8.8"}) {
    const auto address = boost::asio::ip::make_address(literal);
    EXPECT_EQ(fptn::tunnel::FromIpKey(fptn::tunnel::ToIpKey(address)), address)
        << literal;
  }
}

// ── the published lists, end to end ─────────────────────────────────────────

// Opt-in, because the real lists live in the app repo rather than here:
//
//   FPTN_GEO_DAT_DIR=../../../../FptnVPNTests/Fixtures ./GeoRoutingPolicyTest
//
// This is the only test that runs the whole chain -- .dat bytes, verdict map,
// compiler, mapped rule set, policy -- on the data that actually ships. The
// unit tests above use hand-built inputs precisely so they keep passing when
// upstream republishes; this one is where a real regression shows up.
TEST(GeoRoutingPolicyPublishedTest, RoutesTheRealListsEndToEnd) {
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

  const auto geoip_bytes = read("geoip.dat");
  const auto geosite_bytes = read("geosite.dat");
  ASSERT_FALSE(geoip_bytes.empty()) << "geoip.dat not found under " << dir;
  ASSERT_FALSE(geosite_bytes.empty()) << "geosite.dat not found under " << dir;

  const auto ip = fptn::geo::GeoDatParser::ParseGeoIp(geoip_bytes);
  const auto site = fptn::geo::GeoDatParser::ParseGeoSite(geosite_bytes);
  ASSERT_TRUE(ip.ok());
  ASSERT_TRUE(site.ok());

  const auto built = fptn::geo::BuildGeoInputs(
      ip.groups, site.groups, fptn::geo::DefaultVerdictMap());

  GeoCompileOptions options;
  options.default_action = GeoAction::fptn;
  options.bare_hostname_is_direct = built.report.bare_hostname_is_direct;
  const auto compiled = GeoCompiler::Compile(built.inputs, options);
  ASSERT_TRUE(compiled.ok) << compiled.error;

  const TempArtifact artifact(compiled.bytes);
  const auto rules = std::make_shared<GeoRuleSet>();
  ASSERT_EQ(rules->Open(artifact.path()), fptn::geo::GeoLoadError::none);

  // The flattening is the reason this is worth doing at all: 42k published
  // ranges collapse into far fewer disjoint intervals, and the whole artifact
  // stays small enough to map in a jetsam-constrained extension.
  std::printf(
      "[geo] %u ipv4 rules -> %u intervals, %u ipv6, %u domains (%u in), "
      "%u substrings, %u pairs, artifact %zu bytes\n",
      compiled.stats.ipv4_rules_in, compiled.stats.ipv4_intervals_out,
      compiled.stats.ipv6_rules, compiled.stats.domain_rules_out,
      compiled.stats.domain_rules_in, compiled.stats.substring_rules,
      compiled.stats.pair_rules, compiled.bytes.size());
  EXPECT_LT(compiled.bytes.size(), 1024u * 1024u);

  const GeoRoutingPolicy policy(rules, RouteAction::fptn_l4);

  // RFC1918 must never tunnel, whatever else changes upstream.
  EXPECT_EQ(policy.Decide(FlowTo("192.168.1.1"), ""), RouteAction::direct);
  EXPECT_EQ(policy.Decide(FlowTo("10.0.0.1"), ""), RouteAction::direct);

  // A dotless name is a device on the local network.
  EXPECT_EQ(policy.Decide(FlowTo("192.168.1.50"), "nas"), RouteAction::direct);

  // Names from groups whose verdicts are documented, not inferred.
  EXPECT_EQ(policy.Decide(FlowTo("17.253.144.10"), "gs.apple.com"),
      RouteAction::direct);
  EXPECT_EQ(policy.Decide(FlowTo("1.1.1.1"), "www.youtube.com"),
      RouteAction::fptn_l4);
  EXPECT_EQ(policy.Decide(FlowTo("1.1.1.1"),
                "0123456789nonexistent.com"),
      RouteAction::drop);

  // The reduced regex, reached through the pair table.
  EXPECT_EQ(policy.Decide(FlowTo("1.1.1.1"),
                "github-production-release-asset-2e65be.s3.amazonaws.com"),
      RouteAction::fptn_l4);

  // An address with no name attributed to it, answered by the IPv4 table.
  EXPECT_EQ(policy.Decide(FlowTo("77.88.8.8"), ""), RouteAction::direct);
}

}  // namespace
