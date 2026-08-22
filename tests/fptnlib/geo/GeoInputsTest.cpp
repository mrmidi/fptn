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

using fptn::geo::AppendDomainOverrides;
using fptn::geo::BuildGeoInputs;
using fptn::geo::DefaultVerdictMap;
using fptn::geo::GeoAction;
using fptn::geo::GeoCompileInputs;
using fptn::geo::GeoCompileOptions;
using fptn::geo::GeoCompiler;
using fptn::geo::GeoDatDomain;
using fptn::geo::GeoDatDomainType;
using fptn::geo::GeoDatSiteGroup;
using fptn::geo::GeoDomainInput;
using fptn::geo::GeoDomainKind;
using fptn::geo::GeoInputsResult;
using fptn::geo::GeoRoutingPolicy;
using fptn::geo::GeoRuleSet;
using fptn::geo::ParseDomainList;
using fptn::tunnel::FlowMetadata;
using fptn::tunnel::RouteAction;

// Helper to write and map an artifact in a temporary file for verification
class TempArtifact {
 public:
  explicit TempArtifact(const std::vector<std::uint8_t>& bytes) {
    char name[] = "/tmp/fptn-geo-inputs-test-XXXXXX";
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
  ~TempArtifact() {
    if (!path_.empty()) {
      std::remove(path_.c_str());
    }
  }

  TempArtifact(const TempArtifact&) = delete;
  TempArtifact& operator=(const TempArtifact&) = delete;

  const std::string& path() const { return path_; }

 private:
  std::string path_;
};

class MappedRules {
 public:
  explicit MappedRules(const GeoCompileInputs& inputs) {
    GeoCompileOptions options;
    options.default_action = GeoAction::fptn;
    options.bare_hostname_is_direct = true;
    const auto compiled = GeoCompiler::Compile(inputs, options);
    EXPECT_TRUE(compiled.ok) << "Compilation failed: " << compiled.error;
    file_ = std::make_unique<TempArtifact>(compiled.bytes);
    rules_ = std::make_shared<GeoRuleSet>();
    const auto load_err = rules_->Open(file_->path(), /*verify_checksum=*/true);
    EXPECT_EQ(load_err, fptn::geo::GeoLoadError::none);
  }

  std::shared_ptr<GeoRuleSet> rules() const { return rules_; }

 private:
  std::unique_ptr<TempArtifact> file_;
  std::shared_ptr<GeoRuleSet> rules_;
};

TEST(GeoInputsOverrideTest, ParseDomainList_BasicFormats) {
  const std::string text = R"(
    # Basic domain formats
    domain:yandex.ru
    full:api.yandex.ru
    *.vk.com
    .gosuslugi.ru
    mail.ru
  )";

  const auto rules = ParseDomainList(text);
  ASSERT_EQ(rules.size(), 5u);

  EXPECT_EQ(rules[0].value, "yandex.ru");
  EXPECT_EQ(rules[0].kind, GeoDomainKind::suffix);
  EXPECT_EQ(rules[0].action, GeoAction::direct);

  EXPECT_EQ(rules[1].value, "api.yandex.ru");
  EXPECT_EQ(rules[1].kind, GeoDomainKind::exact);
  EXPECT_EQ(rules[1].action, GeoAction::direct);

  EXPECT_EQ(rules[2].value, "vk.com");
  EXPECT_EQ(rules[2].kind, GeoDomainKind::suffix);
  EXPECT_EQ(rules[2].action, GeoAction::direct);

  EXPECT_EQ(rules[3].value, "gosuslugi.ru");
  EXPECT_EQ(rules[3].kind, GeoDomainKind::suffix);
  EXPECT_EQ(rules[3].action, GeoAction::direct);

  EXPECT_EQ(rules[4].value, "mail.ru");
  EXPECT_EQ(rules[4].kind, GeoDomainKind::suffix);
  EXPECT_EQ(rules[4].action, GeoAction::direct);
}

TEST(GeoInputsOverrideTest, ParseDomainList_ActionPrefixes) {
  const std::string text = R"(
    direct:domain:rutracker.org
    fptn:blocked-site.com
    drop:full:ads.yandex.ru
    reject:tracker.example.com
  )";

  const auto rules = ParseDomainList(text);
  ASSERT_EQ(rules.size(), 4u);

  EXPECT_EQ(rules[0].value, "rutracker.org");
  EXPECT_EQ(rules[0].kind, GeoDomainKind::suffix);
  EXPECT_EQ(rules[0].action, GeoAction::direct);

  EXPECT_EQ(rules[1].value, "blocked-site.com");
  EXPECT_EQ(rules[1].kind, GeoDomainKind::suffix);
  EXPECT_EQ(rules[1].action, GeoAction::fptn);

  EXPECT_EQ(rules[2].value, "ads.yandex.ru");
  EXPECT_EQ(rules[2].kind, GeoDomainKind::exact);
  EXPECT_EQ(rules[2].action, GeoAction::drop);

  EXPECT_EQ(rules[3].value, "tracker.example.com");
  EXPECT_EQ(rules[3].kind, GeoDomainKind::suffix);
  EXPECT_EQ(rules[3].action, GeoAction::reject);
}

TEST(GeoInputsOverrideTest, ParseDomainList_CommentsAndWhitespace) {
  const std::string text = R"(
    # Full line comment
    // Another comment style
       
    domain:yandex.ru  # Inline comment
    full:api.yandex.ru   // Inline double-slash comment
    
    # End comment
  )";

  const auto rules = ParseDomainList(text);
  ASSERT_EQ(rules.size(), 2u);
  EXPECT_EQ(rules[0].value, "yandex.ru");
  EXPECT_EQ(rules[0].kind, GeoDomainKind::suffix);
  EXPECT_EQ(rules[1].value, "api.yandex.ru");
  EXPECT_EQ(rules[1].kind, GeoDomainKind::exact);
}

TEST(GeoInputsOverrideTest, ParseDomainList_DeduplicationAndSubsumption) {
  const std::string text = R"(
    # Mixed cases and duplicates
    domain:Yandex.RU
    yandex.ru
    DOMAIN:yandex.ru
    
    # Suffix subsumes exact
    full:vk.com
    domain:vk.com
    
    # Suffix seen first, exact seen later: suffix still wins
    domain:gosuslugi.ru
    full:gosuslugi.ru
  )";

  const auto rules = ParseDomainList(text);
  ASSERT_EQ(rules.size(), 3u);

  // Yandex deduplicated to single entry
  EXPECT_EQ(rules[0].value, "yandex.ru");
  EXPECT_EQ(rules[0].kind, GeoDomainKind::suffix);

  // VK deduplicated to suffix
  EXPECT_EQ(rules[1].value, "vk.com");
  EXPECT_EQ(rules[1].kind, GeoDomainKind::suffix);

  // Gosuslugi deduplicated to suffix
  EXPECT_EQ(rules[2].value, "gosuslugi.ru");
  EXPECT_EQ(rules[2].kind, GeoDomainKind::suffix);
}

TEST(GeoInputsOverrideTest, AppendDomainOverrides_AddAndReplace) {
  // Simulate base inputs from Geo DB with some domains set to fptn
  GeoInputsResult base_result;
  base_result.inputs.domains.push_back(
      GeoDomainInput{GeoDomainKind::suffix, "yandex.ru", GeoAction::fptn});
  base_result.inputs.domains.push_back(
      GeoDomainInput{GeoDomainKind::exact, "auth.gosuslugi.ru", GeoAction::drop});
  base_result.inputs.domains.push_back(
      GeoDomainInput{GeoDomainKind::suffix, "existing-fptn.org", GeoAction::fptn});

  // Git override list: yandex.ru should become direct, gosuslugi.ru added as direct suffix,
  // new-site.ru added as direct
  const std::string git_list = R"(
    domain:yandex.ru
    domain:gosuslugi.ru
    domain:new-site.ru
  )";
  const auto overrides = ParseDomainList(git_list, GeoAction::direct);

  AppendDomainOverrides(base_result, overrides);

  // Check stats: 2 added (gosuslugi.ru, new-site.ru), 2 replaced (yandex.ru, auth.gosuslugi.ru)
  EXPECT_EQ(base_result.report.domain_overrides_added, 2u);
  EXPECT_EQ(base_result.report.domain_overrides_replaced, 2u);

  // Verify that yandex.ru is now GeoAction::direct
  bool found_yandex = false;
  bool found_gosuslugi = false;
  bool found_new_site = false;
  bool found_existing = false;

  for (const auto& d : base_result.inputs.domains) {
    if (d.value == "yandex.ru") {
      found_yandex = true;
      EXPECT_EQ(d.action, GeoAction::direct);
      EXPECT_EQ(d.kind, GeoDomainKind::suffix);
    } else if (d.value == "gosuslugi.ru") {
      found_gosuslugi = true;
      EXPECT_EQ(d.action, GeoAction::direct);
    } else if (d.value == "new-site.ru") {
      found_new_site = true;
      EXPECT_EQ(d.action, GeoAction::direct);
    } else if (d.value == "existing-fptn.org") {
      found_existing = true;
      EXPECT_EQ(d.action, GeoAction::fptn);
    }
  }

  EXPECT_TRUE(found_yandex);
  EXPECT_TRUE(found_gosuslugi);
  EXPECT_TRUE(found_new_site);
  EXPECT_TRUE(found_existing);
}

TEST(GeoInputsOverrideTest, Precedence_GitListBeatsGeoDb) {
  // 1. Build Geo DB site groups where "RU-SERVICES" is set to fptn
  std::vector<GeoDatSiteGroup> site_groups = {
      GeoDatSiteGroup{
          .name = "RU-SERVICES",
          .domains = {
              GeoDatDomain{.type = GeoDatDomainType::root_domain, .value = "yandex.ru"},
              GeoDatDomain{.type = GeoDatDomainType::root_domain, .value = "mail.ru"},
              GeoDatDomain{.type = GeoDatDomainType::full, .value = "special.service.ru"},
          },
      },
  };

  auto verdict_map = DefaultVerdictMap();
  verdict_map.site["RU-SERVICES"] = GeoAction::fptn;  // In Geo DB, this group is fptn

  // 2. Build base inputs
  auto base_result = BuildGeoInputs({}, site_groups, verdict_map);

  // 3. Git list overrides yandex.ru and special.service.ru to direct
  const std::string git_list = R"(
    # Git list says these MUST be direct
    domain:yandex.ru
    full:special.service.ru
  )";
  const auto overrides = ParseDomainList(git_list, GeoAction::direct);
  AppendDomainOverrides(base_result, overrides);

  // 4. Compile and map rules
  MappedRules mapped(base_result.inputs);
  GeoRoutingPolicy policy(mapped.rules(), RouteAction::fptn_l4);

  auto flow_to = [](const std::string& address) {
    FlowMetadata flow;
    flow.id = 1;
    flow.protocol = fptn::tunnel::TransportProtocol::tcp;
    flow.destination.address = boost::asio::ip::make_address(address);
    flow.destination.port = 443;
    return flow;
  };

  // 5. Test routing decisions:
  // yandex.ru & subdomains MUST route direct (overridden by git list)
  EXPECT_EQ(policy.Decide(flow_to("1.1.1.1"), "yandex.ru"), RouteAction::direct);
  EXPECT_EQ(policy.Decide(flow_to("1.1.1.1"), "mail.yandex.ru"), RouteAction::direct);
  EXPECT_EQ(policy.Decide(flow_to("1.1.1.1"), "special.service.ru"), RouteAction::direct);

  // mail.ru was NOT in git list, so it retains Geo DB's verdict (fptn_l4)
  EXPECT_EQ(policy.Decide(flow_to("1.1.1.1"), "mail.ru"), RouteAction::fptn_l4);
  EXPECT_EQ(policy.Decide(flow_to("1.1.1.1"), "cloud.mail.ru"), RouteAction::fptn_l4);
}

TEST(GeoInputsOverrideTest, Precedence_SuffixOverrideCoversSubdomains) {
  // Geo DB has specific subdomain rules as fptn
  std::vector<GeoDatSiteGroup> site_groups = {
      GeoDatSiteGroup{
          .name = "BLOCKED-SUBDOMAINS",
          .domains = {
              GeoDatDomain{.type = GeoDatDomainType::full, .value = "music.yandex.ru"},
              GeoDatDomain{.type = GeoDatDomainType::full, .value = "video.yandex.ru"},
          },
      },
  };

  auto verdict_map = DefaultVerdictMap();
  verdict_map.site["BLOCKED-SUBDOMAINS"] = GeoAction::fptn;

  auto base_result = BuildGeoInputs({}, site_groups, verdict_map);

  // Git list adds entire yandex.ru suffix as direct
  const std::string git_list = "domain:yandex.ru\n";
  const auto overrides = ParseDomainList(git_list, GeoAction::direct);
  AppendDomainOverrides(base_result, overrides);

  auto flow_to = [](const std::string& address) {
    FlowMetadata flow;
    flow.id = 1;
    flow.protocol = fptn::tunnel::TransportProtocol::tcp;
    flow.destination.address = boost::asio::ip::make_address(address);
    flow.destination.port = 443;
    return flow;
  };

  MappedRules mapped(base_result.inputs);
  GeoRoutingPolicy policy(mapped.rules(), RouteAction::fptn_l4);

  // Subdomain matching should resolve to direct
  EXPECT_EQ(policy.Decide(flow_to("1.1.1.1"), "yandex.ru"), RouteAction::direct);
  EXPECT_EQ(policy.Decide(flow_to("1.1.1.1"), "music.yandex.ru"), RouteAction::direct);
  EXPECT_EQ(policy.Decide(flow_to("1.1.1.1"), "video.yandex.ru"), RouteAction::direct);
  EXPECT_EQ(policy.Decide(flow_to("1.1.1.1"), "other.yandex.ru"), RouteAction::direct);
}

}  // namespace
