/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <gtest/gtest.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "fptn-protocol-lib/geo/geo_compiler.h"
#include "fptn-protocol-lib/geo/geo_rule_set.h"

namespace {

using fptn::geo::GeoAction;
using fptn::geo::GeoCidrInput;
using fptn::geo::GeoCompileInputs;
using fptn::geo::GeoCompiler;
using fptn::geo::GeoCompileOptions;
using fptn::geo::GeoDomainInput;
using fptn::geo::GeoDomainKind;
using fptn::geo::GeoLoadError;
using fptn::geo::GeoPairInput;
using fptn::geo::GeoRuleSet;
using fptn::geo::GeoSubstringInput;

std::uint32_t Ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c,
    std::uint8_t d) {
  return (static_cast<std::uint32_t>(a) << 24) |
         (static_cast<std::uint32_t>(b) << 16) |
         (static_cast<std::uint32_t>(c) << 8) | d;
}

GeoCidrInput V4(std::uint32_t base, std::uint8_t prefix, GeoAction action) {
  GeoCidrInput cidr;
  cidr.is_ipv6 = false;
  cidr.low = base;
  cidr.prefix = prefix;
  cidr.action = action;
  return cidr;
}

GeoDomainInput Suffix(const std::string& value, GeoAction action) {
  return GeoDomainInput{GeoDomainKind::suffix, value, action};
}

// Writes the artifact somewhere the test can map it, and removes it on
// destruction. Deliberately writes the file whole: the production writer must
// rename() into place rather than rewrite, because truncating a mapped file
// turns the next page touch into SIGBUS.
class TempArtifact {
 public:
  explicit TempArtifact(const std::vector<std::uint8_t>& bytes) {
    char name[] = "/tmp/fptn-geo-XXXXXX";
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

std::vector<std::uint8_t> CompileOrDie(const GeoCompileInputs& inputs,
    GeoAction default_action = GeoAction::fptn) {
  GeoCompileOptions options;
  options.default_action = default_action;
  const auto result = GeoCompiler::Compile(inputs, options);
  EXPECT_TRUE(result.ok) << result.error;
  return result.bytes;
}

}  // namespace

TEST(GeoCompilerTest, ReversesLabels) {
  EXPECT_EQ(GeoCompiler::ReverseLabels("smtp.mail.ru"), "ru.mail.smtp");
  EXPECT_EQ(GeoCompiler::ReverseLabels("mail.ru"), "ru.mail");
  EXPECT_EQ(GeoCompiler::ReverseLabels("ru"), "ru");
  EXPECT_EQ(GeoCompiler::ReverseLabels(""), "");
}

TEST(GeoRuleSetTest, RoundTripsASingleRange) {
  GeoCompileInputs inputs;
  inputs.cidrs.push_back(V4(Ipv4(10, 0, 0, 0), 8, GeoAction::direct));

  TempArtifact artifact(CompileOrDie(inputs));
  GeoRuleSet rules;
  ASSERT_EQ(rules.Open(artifact.path()), GeoLoadError::none);

  EXPECT_EQ(rules.LookupIpv4(Ipv4(10, 0, 0, 1)), GeoAction::direct);
  EXPECT_EQ(rules.LookupIpv4(Ipv4(10, 255, 255, 255)), GeoAction::direct);
  EXPECT_EQ(rules.LookupIpv4(Ipv4(11, 0, 0, 0)), GeoAction::none);
  EXPECT_EQ(rules.LookupIpv4(Ipv4(9, 255, 255, 255)), GeoAction::none);
  EXPECT_EQ(rules.default_action(), GeoAction::fptn);
}

// The published data is 98% overlap: a /32 whitelist entry sitting inside a /23
// direct range. If the flattener got precedence wrong, this is where it shows.
TEST(GeoRuleSetTest, LongestPrefixWinsOverAContainingRange) {
  GeoCompileInputs inputs;
  inputs.cidrs.push_back(V4(Ipv4(5, 8, 42, 0), 23, GeoAction::direct));
  inputs.cidrs.push_back(V4(Ipv4(5, 8, 43, 1), 32, GeoAction::reject));

  TempArtifact artifact(CompileOrDie(inputs));
  GeoRuleSet rules;
  ASSERT_EQ(rules.Open(artifact.path()), GeoLoadError::none);

  EXPECT_EQ(rules.LookupIpv4(Ipv4(5, 8, 43, 1)), GeoAction::reject);
  EXPECT_EQ(rules.LookupIpv4(Ipv4(5, 8, 43, 0)), GeoAction::direct);
  EXPECT_EQ(rules.LookupIpv4(Ipv4(5, 8, 43, 2)), GeoAction::direct);
  EXPECT_EQ(rules.LookupIpv4(Ipv4(5, 8, 44, 0)), GeoAction::none);
}

TEST(GeoRuleSetTest, MergesAdjacentRangesWithTheSameVerdict) {
  GeoCompileInputs inputs;
  // Two halves of a /23, same verdict: indistinguishable to a lookup, so the
  // compiler must not keep both. This merging is what takes 42k ranges to 15k.
  inputs.cidrs.push_back(V4(Ipv4(1, 2, 2, 0), 24, GeoAction::direct));
  inputs.cidrs.push_back(V4(Ipv4(1, 2, 3, 0), 24, GeoAction::direct));

  GeoCompileOptions options;
  const auto result = GeoCompiler::Compile(inputs, options);
  ASSERT_TRUE(result.ok);
  // Entry at 0 (none), one at the start of the merged run, one after it.
  EXPECT_EQ(result.stats.ipv4_intervals_out, 3u);

  TempArtifact artifact(result.bytes);
  GeoRuleSet rules;
  ASSERT_EQ(rules.Open(artifact.path()), GeoLoadError::none);
  EXPECT_EQ(rules.LookupIpv4(Ipv4(1, 2, 2, 5)), GeoAction::direct);
  EXPECT_EQ(rules.LookupIpv4(Ipv4(1, 2, 3, 5)), GeoAction::direct);
  EXPECT_EQ(rules.LookupIpv4(Ipv4(1, 2, 4, 0)), GeoAction::none);
}

TEST(GeoRuleSetTest, CoversTheWholeAddressSpace) {
  GeoCompileInputs inputs;
  inputs.cidrs.push_back(V4(0, 0, GeoAction::direct));

  TempArtifact artifact(CompileOrDie(inputs));
  GeoRuleSet rules;
  ASSERT_EQ(rules.Open(artifact.path()), GeoLoadError::none);
  EXPECT_EQ(rules.LookupIpv4(0), GeoAction::direct);
  EXPECT_EQ(rules.LookupIpv4(0xFFFFFFFFu), GeoAction::direct);
}

TEST(GeoRuleSetTest, MatchesDomainSuffixesLabelAware) {
  GeoCompileInputs inputs;
  inputs.domains.push_back(Suffix("mail.ru", GeoAction::reject));
  inputs.domains.push_back(Suffix("4pda.ru", GeoAction::fptn));

  TempArtifact artifact(CompileOrDie(inputs));
  GeoRuleSet rules;
  ASSERT_EQ(rules.Open(artifact.path()), GeoLoadError::none);

  EXPECT_EQ(rules.LookupDomain("mail.ru"), GeoAction::reject);
  EXPECT_EQ(rules.LookupDomain("smtp.mail.ru"), GeoAction::reject);
  EXPECT_EQ(rules.LookupDomain("a.b.mail.ru"), GeoAction::reject);
  EXPECT_EQ(rules.LookupDomain("MAIL.RU"), GeoAction::reject);
  EXPECT_EQ(rules.LookupDomain("mail.ru."), GeoAction::reject);
  // Ends with the same characters but is a different domain.
  EXPECT_EQ(rules.LookupDomain("notmail.ru"), GeoAction::none);
  EXPECT_EQ(rules.LookupDomain("example.org"), GeoAction::none);
}

TEST(GeoRuleSetTest, LongerSuffixBeatsShorterOne) {
  GeoCompileInputs inputs;
  inputs.domains.push_back(Suffix("example.com", GeoAction::fptn));
  inputs.domains.push_back(Suffix("mail.example.com", GeoAction::direct));

  TempArtifact artifact(CompileOrDie(inputs));
  GeoRuleSet rules;
  ASSERT_EQ(rules.Open(artifact.path()), GeoLoadError::none);

  EXPECT_EQ(rules.LookupDomain("smtp.mail.example.com"), GeoAction::direct);
  EXPECT_EQ(rules.LookupDomain("www.example.com"), GeoAction::fptn);
}

TEST(GeoRuleSetTest, ExactRulesDoNotMatchSubdomains) {
  GeoCompileInputs inputs;
  inputs.domains.push_back(
      GeoDomainInput{GeoDomainKind::exact, "www.example.com", GeoAction::direct});

  TempArtifact artifact(CompileOrDie(inputs));
  GeoRuleSet rules;
  ASSERT_EQ(rules.Open(artifact.path()), GeoLoadError::none);

  EXPECT_EQ(rules.LookupDomain("www.example.com"), GeoAction::direct);
  EXPECT_EQ(rules.LookupDomain("a.www.example.com"), GeoAction::none);
}

TEST(GeoRuleSetTest, SubstringRulesApplyWhenTheSortedTableMisses) {
  GeoCompileInputs inputs;
  inputs.substrings.push_back(GeoSubstringInput{"openai.", GeoAction::fptn});

  TempArtifact artifact(CompileOrDie(inputs));
  GeoRuleSet rules;
  ASSERT_EQ(rules.Open(artifact.path()), GeoLoadError::none);

  // The trailing dot is what makes these substring rules: they must catch
  // every TLD the service uses.
  EXPECT_EQ(rules.LookupDomain("openai.com"), GeoAction::fptn);
  EXPECT_EQ(rules.LookupDomain("api.openai.org"), GeoAction::fptn);
  EXPECT_EQ(rules.LookupDomain("example.com"), GeoAction::none);
}

TEST(GeoRuleSetTest, SortedTableWinsOverSubstringRules) {
  GeoCompileInputs inputs;
  inputs.domains.push_back(Suffix("api.openai.com", GeoAction::direct));
  inputs.substrings.push_back(GeoSubstringInput{"openai.", GeoAction::fptn});

  TempArtifact artifact(CompileOrDie(inputs));
  GeoRuleSet rules;
  ASSERT_EQ(rules.Open(artifact.path()), GeoLoadError::none);

  EXPECT_EQ(rules.LookupDomain("api.openai.com"), GeoAction::direct);
  EXPECT_EQ(rules.LookupDomain("chat.openai.com"), GeoAction::fptn);
}

// Stands in for the regexes, all of which reduce to this shape.
TEST(GeoRuleSetTest, MatchesContainsPlusSuffixPairs) {
  GeoCompileInputs inputs;
  inputs.pairs.push_back(GeoPairInput{"github-production-release-asset-",
      ".s3.amazonaws.com", GeoAction::fptn});

  TempArtifact artifact(CompileOrDie(inputs));
  GeoRuleSet rules;
  ASSERT_EQ(rules.Open(artifact.path()), GeoLoadError::none);

  EXPECT_EQ(
      rules.LookupDomain("github-production-release-asset-2e65be.s3.amazonaws.com"),
      GeoAction::fptn);
  // Right suffix, wrong prefix.
  EXPECT_EQ(rules.LookupDomain("other.s3.amazonaws.com"), GeoAction::none);
  // Right prefix, wrong suffix.
  EXPECT_EQ(
      rules.LookupDomain("github-production-release-asset-2e65be.example.com"),
      GeoAction::none);
}

TEST(GeoRuleSetTest, BareHostnamesAreLocal) {
  GeoCompileInputs inputs;
  inputs.domains.push_back(Suffix("example.com", GeoAction::fptn));

  GeoCompileOptions options;
  options.bare_hostname_is_direct = true;
  const auto result = GeoCompiler::Compile(inputs, options);
  ASSERT_TRUE(result.ok);

  TempArtifact artifact(result.bytes);
  GeoRuleSet rules;
  ASSERT_EQ(rules.Open(artifact.path()), GeoLoadError::none);

  EXPECT_EQ(rules.LookupDomain("nas"), GeoAction::direct);
  EXPECT_EQ(rules.LookupDomain("router"), GeoAction::direct);
  EXPECT_EQ(rules.LookupDomain("example.com"), GeoAction::fptn);
}

TEST(GeoRuleSetTest, MatchesIpv6LongestPrefix) {
  GeoCompileInputs inputs;
  GeoCidrInput broad;
  broad.is_ipv6 = true;
  broad.high = 0x2a020000UL;
  broad.high <<= 32;
  broad.prefix = 32;
  broad.action = GeoAction::direct;
  inputs.cidrs.push_back(broad);

  GeoCidrInput narrow = broad;
  narrow.prefix = 128;
  narrow.low = 1;
  narrow.action = GeoAction::reject;
  inputs.cidrs.push_back(narrow);

  TempArtifact artifact(CompileOrDie(inputs));
  GeoRuleSet rules;
  ASSERT_EQ(rules.Open(artifact.path()), GeoLoadError::none);

  EXPECT_EQ(rules.LookupIpv6(broad.high, 1), GeoAction::reject);
  EXPECT_EQ(rules.LookupIpv6(broad.high, 2), GeoAction::direct);
  EXPECT_EQ(rules.LookupIpv6(0, 1), GeoAction::none);
}

TEST(GeoRuleSetTest, ReportsConflictingDomainVerdicts) {
  GeoCompileInputs inputs;
  inputs.domains.push_back(Suffix("example.com", GeoAction::direct));
  inputs.domains.push_back(Suffix("example.com", GeoAction::fptn));

  GeoCompileOptions options;
  const auto result = GeoCompiler::Compile(inputs, options);
  ASSERT_TRUE(result.ok);
  // Deduplicated to one entry, but the disagreement is surfaced rather than
  // hidden: it means the source lists contradict themselves.
  EXPECT_EQ(result.stats.domain_rules_out, 1u);
  EXPECT_EQ(result.stats.domain_conflicts, 1u);
}

// Two groups genuinely disagree about a handful of names in the published
// lists (`epicgames.com` is in both EPICGAMES and CATEGORY-GEOBLOCK-RU). The
// winner must not depend on which group the file happens to list first.
TEST(GeoRuleSetTest, ConflictingVerdictsResolveByPrecedenceNotInputOrder) {
  const auto compile = [](GeoAction first, GeoAction second) {
    GeoCompileInputs inputs;
    inputs.domains.push_back(Suffix("example.com", first));
    inputs.domains.push_back(Suffix("example.com", second));
    const auto bytes = CompileOrDie(inputs);
    TempArtifact artifact(bytes);
    GeoRuleSet rules;
    EXPECT_EQ(rules.Open(artifact.path()), GeoLoadError::none);
    return rules.LookupDomain("example.com");
  };

  // Tunnelling beats direct: a geo-blocked name answered `direct` is broken,
  // while the reverse only costs server traffic.
  EXPECT_EQ(compile(GeoAction::direct, GeoAction::fptn), GeoAction::fptn);
  EXPECT_EQ(compile(GeoAction::fptn, GeoAction::direct), GeoAction::fptn);

  // An explicit block beats everything: it was listed on purpose.
  EXPECT_EQ(compile(GeoAction::fptn, GeoAction::drop), GeoAction::drop);
  EXPECT_EQ(compile(GeoAction::drop, GeoAction::fptn), GeoAction::drop);
  EXPECT_EQ(compile(GeoAction::direct, GeoAction::reject), GeoAction::reject);
  EXPECT_EQ(compile(GeoAction::reject, GeoAction::direct), GeoAction::reject);
}

// Kind and verdict are resolved independently: a suffix rule subsumes an exact
// one for the same name, whichever of the two won the verdict.
TEST(GeoRuleSetTest, ASuffixRuleSubsumesAnExactRuleForTheSameName) {
  GeoCompileInputs inputs;
  inputs.domains.push_back(GeoDomainInput{
      GeoDomainKind::exact, "example.com", GeoAction::direct});
  inputs.domains.push_back(Suffix("example.com", GeoAction::direct));

  const auto bytes = CompileOrDie(inputs);
  TempArtifact artifact(bytes);
  GeoRuleSet rules;
  ASSERT_EQ(rules.Open(artifact.path()), GeoLoadError::none);

  EXPECT_EQ(rules.LookupDomain("example.com"), GeoAction::direct);
  EXPECT_EQ(rules.LookupDomain("www.example.com"), GeoAction::direct);
}

// ── Refusing bad artifacts ─────────────────────────────────────────────────
//
// This runs in the process that routes packets. Every one of these must be a
// clean refusal, never a wild read.

TEST(GeoRuleSetTest, RefusesAMissingFile) {
  GeoRuleSet rules;
  EXPECT_EQ(rules.Open("/nonexistent/geo.fptngeo"), GeoLoadError::cannot_open);
  EXPECT_FALSE(rules.IsOpen());
}

TEST(GeoRuleSetTest, RefusesAFileSmallerThanTheHeader) {
  TempArtifact artifact(std::vector<std::uint8_t>(16, 0));
  GeoRuleSet rules;
  EXPECT_EQ(rules.Open(artifact.path()), GeoLoadError::too_small);
}

TEST(GeoRuleSetTest, RefusesForeignFiles) {
  GeoCompileInputs inputs;
  inputs.domains.push_back(Suffix("example.com", GeoAction::fptn));
  auto bytes = CompileOrDie(inputs);
  bytes[0] = 'X';

  TempArtifact artifact(bytes);
  GeoRuleSet rules;
  EXPECT_EQ(rules.Open(artifact.path()), GeoLoadError::bad_magic);
}

TEST(GeoRuleSetTest, RefusesAnUnknownFormatVersion) {
  GeoCompileInputs inputs;
  inputs.domains.push_back(Suffix("example.com", GeoAction::fptn));
  auto bytes = CompileOrDie(inputs);
  bytes[8] = 0xFE;  // format_version low byte

  TempArtifact artifact(bytes);
  GeoRuleSet rules;
  EXPECT_EQ(rules.Open(artifact.path()), GeoLoadError::unsupported_version);
}

TEST(GeoRuleSetTest, RefusesATruncatedArtifact) {
  GeoCompileInputs inputs;
  inputs.cidrs.push_back(V4(Ipv4(10, 0, 0, 0), 8, GeoAction::direct));
  inputs.domains.push_back(Suffix("example.com", GeoAction::fptn));
  auto bytes = CompileOrDie(inputs);
  bytes.resize(bytes.size() - 32);

  TempArtifact artifact(bytes);
  GeoRuleSet rules;
  // The header still claims the original size, which no longer matches.
  EXPECT_EQ(rules.Open(artifact.path()), GeoLoadError::size_mismatch);
}

TEST(GeoRuleSetTest, RefusesATamperedBody) {
  GeoCompileInputs inputs;
  inputs.domains.push_back(Suffix("example.com", GeoAction::fptn));
  auto bytes = CompileOrDie(inputs);
  // Flip a byte in the blob, leaving every length and offset intact.
  bytes[bytes.size() - 1] ^= 0xFF;

  TempArtifact artifact(bytes);
  GeoRuleSet rules;
  EXPECT_EQ(rules.Open(artifact.path()), GeoLoadError::checksum_mismatch);
}

TEST(GeoRuleSetTest, SkipsTheChecksumWhenAsked) {
  GeoCompileInputs inputs;
  inputs.domains.push_back(Suffix("example.com", GeoAction::fptn));
  auto bytes = CompileOrDie(inputs);
  bytes[bytes.size() - 1] ^= 0xFF;

  TempArtifact artifact(bytes);
  GeoRuleSet rules;
  EXPECT_EQ(rules.Open(artifact.path(), /*verify_checksum=*/false),
      GeoLoadError::none);
}

TEST(GeoRuleSetTest, HandlesAnEmptyRuleSet) {
  GeoCompileInputs inputs;
  TempArtifact artifact(CompileOrDie(inputs));
  GeoRuleSet rules;
  ASSERT_EQ(rules.Open(artifact.path()), GeoLoadError::none);

  EXPECT_EQ(rules.LookupIpv4(Ipv4(8, 8, 8, 8)), GeoAction::none);
  EXPECT_EQ(rules.LookupDomain("example.com"), GeoAction::none);
  EXPECT_EQ(rules.domain_count(), 0u);
}

TEST(GeoRuleSetTest, IgnoresMalformedQueries) {
  GeoCompileInputs inputs;
  inputs.domains.push_back(Suffix("example.com", GeoAction::fptn));
  TempArtifact artifact(CompileOrDie(inputs));
  GeoRuleSet rules;
  ASSERT_EQ(rules.Open(artifact.path()), GeoLoadError::none);

  EXPECT_EQ(rules.LookupDomain(""), GeoAction::none);
  EXPECT_EQ(rules.LookupDomain("."), GeoAction::none);
  EXPECT_EQ(rules.LookupDomain(std::string(400, 'a')), GeoAction::none);
}
