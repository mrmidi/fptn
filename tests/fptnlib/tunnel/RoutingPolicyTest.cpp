/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "fptn-protocol-lib/tunnel/routing_policy.h"

namespace {

using namespace fptn::tunnel;

FlowMetadata MakeFlow() {
  FlowMetadata flow;
  flow.id = 1;
  flow.protocol = TransportProtocol::tcp;
  flow.destination.port = 443;
  return flow;
}

TEST(StaticDomainPolicyTest, UnmatchedDomainTakesTheDefaultVerdict) {
  StaticDomainPolicy policy(RouteAction::fptn_l4);
  policy.AddRule("2ip.ru", RouteAction::direct);

  EXPECT_EQ(policy.Decide(MakeFlow(), "example.com"), RouteAction::fptn_l4);
}

TEST(StaticDomainPolicyTest, EmptyDomainTakesTheDefaultVerdict) {
  StaticDomainPolicy policy(RouteAction::fptn_l4);
  policy.AddRule("2ip.ru", RouteAction::direct);

  // An IP-literal connection has no domain to attribute; it must tunnel.
  EXPECT_EQ(policy.Decide(MakeFlow(), ""), RouteAction::fptn_l4);
}

TEST(StaticDomainPolicyTest, ExactDomainMatches) {
  StaticDomainPolicy policy(RouteAction::fptn_l4);
  policy.AddRule("2ip.ru", RouteAction::direct);

  EXPECT_EQ(policy.Decide(MakeFlow(), "2ip.ru"), RouteAction::direct);
}

TEST(StaticDomainPolicyTest, SubdomainsMatchTheRule) {
  StaticDomainPolicy policy(RouteAction::fptn_l4);
  policy.AddRule("mail.ru", RouteAction::reject);

  EXPECT_EQ(policy.Decide(MakeFlow(), "smtp.mail.ru"), RouteAction::reject);
  EXPECT_EQ(
      policy.Decide(MakeFlow(), "a.b.c.mail.ru"), RouteAction::reject);
}

// The whole point of matching at label boundaries.
TEST(StaticDomainPolicyTest, SuffixMatchIsLabelAware) {
  StaticDomainPolicy policy(RouteAction::fptn_l4);
  policy.AddRule("mail.ru", RouteAction::reject);

  EXPECT_EQ(policy.Decide(MakeFlow(), "notmail.ru"), RouteAction::fptn_l4);
  EXPECT_EQ(policy.Decide(MakeFlow(), "xmail.ru"), RouteAction::fptn_l4);
  // A rule is a suffix, never a prefix.
  EXPECT_EQ(policy.Decide(MakeFlow(), "mail.ru.example.com"),
      RouteAction::fptn_l4);
}

TEST(StaticDomainPolicyTest, MoreSpecificRuleWinsOverItsParent) {
  StaticDomainPolicy policy(RouteAction::fptn_l4);
  policy.AddRule("ru", RouteAction::direct);
  policy.AddRule("mail.ru", RouteAction::reject);

  EXPECT_EQ(policy.Decide(MakeFlow(), "mail.ru"), RouteAction::reject);
  EXPECT_EQ(policy.Decide(MakeFlow(), "smtp.mail.ru"), RouteAction::reject);
  EXPECT_EQ(policy.Decide(MakeFlow(), "yandex.ru"), RouteAction::direct);
  EXPECT_EQ(policy.Decide(MakeFlow(), "example.com"), RouteAction::fptn_l4);
}

TEST(StaticDomainPolicyTest, MatchingIsCaseAndDotInsensitive) {
  StaticDomainPolicy policy(RouteAction::fptn_l4);
  policy.AddRule("Mail.RU", RouteAction::reject);

  EXPECT_EQ(policy.Decide(MakeFlow(), "SMTP.Mail.Ru"), RouteAction::reject);
  // Fully-qualified names carry the root dot.
  EXPECT_EQ(policy.Decide(MakeFlow(), "smtp.mail.ru."), RouteAction::reject);
}

TEST(StaticDomainPolicyTest, AcceptsTheExistingDomainRuleSyntax) {
  StaticDomainPolicy policy(RouteAction::fptn_l4);
  policy.AddRules({"domain:2ip.ru", " domain:vk.com ", ".yandex.net"},
      RouteAction::direct);

  EXPECT_EQ(policy.rule_count(), 3u);
  EXPECT_EQ(policy.Decide(MakeFlow(), "2ip.ru"), RouteAction::direct);
  EXPECT_EQ(policy.Decide(MakeFlow(), "m.vk.com"), RouteAction::direct);
  EXPECT_EQ(policy.Decide(MakeFlow(), "cdn.yandex.net"), RouteAction::direct);
}

TEST(StaticDomainPolicyTest, MalformedRulesAreIgnored) {
  StaticDomainPolicy policy(RouteAction::fptn_l4);
  policy.AddRules({"", "   ", "domain:", ".", "a..b"}, RouteAction::direct);

  EXPECT_EQ(policy.rule_count(), 0u);
  EXPECT_EQ(policy.Decide(MakeFlow(), "a.b"), RouteAction::fptn_l4);
}

TEST(StaticDomainPolicyTest, LaterRuleReplacesEarlierOneForSameDomain) {
  StaticDomainPolicy policy(RouteAction::fptn_l4);
  policy.AddRule("ads.example", RouteAction::reject);
  policy.AddRule("ads.example", RouteAction::drop);

  EXPECT_EQ(policy.rule_count(), 1u);
  EXPECT_EQ(policy.Decide(MakeFlow(), "ads.example"), RouteAction::drop);
}

TEST(StaticDomainPolicyTest, AllFourVerdictsAreExpressible) {
  StaticDomainPolicy policy(RouteAction::fptn_l4);
  policy.AddRule("2ip.ru", RouteAction::direct);
  policy.AddRule("mail.ru", RouteAction::reject);
  policy.AddRule("ads.example", RouteAction::drop);

  EXPECT_EQ(policy.Decide(MakeFlow(), "2ip.ru"), RouteAction::direct);
  EXPECT_EQ(policy.Decide(MakeFlow(), "mail.ru"), RouteAction::reject);
  EXPECT_EQ(policy.Decide(MakeFlow(), "ads.example"), RouteAction::drop);
  EXPECT_EQ(policy.Decide(MakeFlow(), "unknown.test"), RouteAction::fptn_l4);
}

TEST(RouteActionTest, EveryVerdictHasAName) {
  EXPECT_STREQ(ToString(RouteAction::direct), "direct");
  EXPECT_STREQ(ToString(RouteAction::fptn_l4), "fptn");
  EXPECT_STREQ(ToString(RouteAction::reject), "reject");
  EXPECT_STREQ(ToString(RouteAction::drop), "drop");
}

}  // namespace
