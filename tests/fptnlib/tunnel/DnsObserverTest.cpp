/*=============================================================================
Copyright (c) 2026 Aleksandr Shabelnikov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "fptn-protocol-lib/tunnel/dns_observer.h"

namespace {

using namespace fptn::tunnel;

IpKey V4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  IpKey key;
  key.version = 4;
  key.bytes[0] = a;
  key.bytes[1] = b;
  key.bytes[2] = c;
  key.bytes[3] = d;
  return key;
}

void PushBe16(std::vector<std::uint8_t>& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value >> 8));
  out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
}

void PushBe32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>(value >> 24));
  out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
  out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
}

// Encodes `a.b.c` as length-prefixed labels terminated by a root label.
void PushName(std::vector<std::uint8_t>& out, const std::string& domain) {
  std::size_t start = 0;
  while (start <= domain.size()) {
    const std::size_t dot = domain.find('.', start);
    const std::size_t end = dot == std::string::npos ? domain.size() : dot;
    const std::size_t length = end - start;
    out.push_back(static_cast<std::uint8_t>(length));
    out.insert(out.end(), domain.begin() + static_cast<long>(start),
        domain.begin() + static_cast<long>(end));
    if (dot == std::string::npos) {
      break;
    }
    start = dot + 1;
  }
  out.push_back(0);
}

struct Answer {
  std::uint16_t type = 1;
  std::uint32_t ttl = 300;
  std::vector<std::uint8_t> rdata;
  // Answer NAME as a compression pointer back to the question (the common
  // real-world encoding), or inline when false.
  bool compressed_name = true;
  std::string inline_name;
};

Answer ARecord(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d,
    std::uint32_t ttl = 300) {
  return Answer{1, ttl, {a, b, c, d}, true, {}};
}

Answer AaaaRecord(std::uint32_t ttl = 300) {
  std::vector<std::uint8_t> rdata(16, 0);
  rdata[0] = 0x20;
  rdata[1] = 0x01;
  rdata[15] = 0x42;
  return Answer{28, ttl, std::move(rdata), true, {}};
}

Answer CnameRecord(const std::string& target, std::uint32_t ttl = 300) {
  std::vector<std::uint8_t> rdata;
  PushName(rdata, target);
  return Answer{5, ttl, std::move(rdata), true, {}};
}

// A full IPv4/UDP/DNS response packet.
std::vector<std::uint8_t> MakeDnsResponse(const std::string& question,
    const std::vector<Answer>& answers, bool is_response = true) {
  std::vector<std::uint8_t> dns;
  PushBe16(dns, 0x1234);
  PushBe16(dns, is_response ? 0x8180 : 0x0100);
  PushBe16(dns, 1);
  PushBe16(dns, static_cast<std::uint16_t>(answers.size()));
  PushBe16(dns, 0);
  PushBe16(dns, 0);
  PushName(dns, question);
  PushBe16(dns, 1);  // QTYPE A
  PushBe16(dns, 1);  // QCLASS IN

  for (const auto& answer : answers) {
    if (answer.compressed_name) {
      // Pointer to offset 12, where the question name starts.
      dns.push_back(0xC0);
      dns.push_back(0x0C);
    } else {
      PushName(dns, answer.inline_name);
    }
    PushBe16(dns, answer.type);
    PushBe16(dns, 1);  // CLASS IN
    PushBe32(dns, answer.ttl);
    PushBe16(dns, static_cast<std::uint16_t>(answer.rdata.size()));
    dns.insert(dns.end(), answer.rdata.begin(), answer.rdata.end());
  }

  const std::size_t udp_length = 8 + dns.size();
  const std::size_t total = 20 + udp_length;

  std::vector<std::uint8_t> packet(20, 0);
  packet[0] = 0x45;
  packet[2] = static_cast<std::uint8_t>(total >> 8);
  packet[3] = static_cast<std::uint8_t>(total & 0xFFu);
  packet[8] = 64;
  packet[9] = 17;  // UDP
  packet[12] = 10;
  packet[13] = 8;
  packet[14] = 0;
  packet[15] = 1;  // src 10.8.0.1 (the resolver)
  packet[16] = 10;
  packet[17] = 8;
  packet[18] = 0;
  packet[19] = 2;  // dst 10.8.0.2 (the app)

  PushBe16(packet, 53);     // src port
  PushBe16(packet, 40000);  // dst port
  PushBe16(packet, static_cast<std::uint16_t>(udp_length));
  PushBe16(packet, 0);  // checksum
  packet.insert(packet.end(), dns.begin(), dns.end());
  return packet;
}

void Feed(DnsObserver& observer, const std::vector<std::uint8_t>& packet) {
  observer.ObservePacket(packet.data(), packet.size());
}

TEST(DnsObserverTest, RecordsARecordAgainstTheQuestionDomain) {
  DnsObserver observer;
  Feed(observer, MakeDnsResponse("2ip.ru", {ARecord(104, 21, 0, 1)}));

  EXPECT_EQ(observer.LookupDomain(V4(104, 21, 0, 1)), "2ip.ru");
  EXPECT_EQ(observer.Counters().mappings_recorded, 1u);
}

TEST(DnsObserverTest, RecordsEveryAddressInAMultiAnswerResponse) {
  DnsObserver observer;
  Feed(observer, MakeDnsResponse("2ip.ru",
                     {ARecord(104, 21, 0, 1), ARecord(104, 21, 0, 2),
                         ARecord(104, 21, 0, 3)}));

  EXPECT_EQ(observer.LookupDomain(V4(104, 21, 0, 1)), "2ip.ru");
  EXPECT_EQ(observer.LookupDomain(V4(104, 21, 0, 2)), "2ip.ru");
  EXPECT_EQ(observer.LookupDomain(V4(104, 21, 0, 3)), "2ip.ru");
}

TEST(DnsObserverTest, RecordsAaaaRecords) {
  DnsObserver observer;
  Feed(observer, MakeDnsResponse("2ip.ru", {AaaaRecord()}));

  IpKey expected;
  expected.version = 6;
  expected.bytes[0] = 0x20;
  expected.bytes[1] = 0x01;
  expected.bytes[15] = 0x42;
  EXPECT_EQ(observer.LookupDomain(expected), "2ip.ru");
}

// A CNAME chain must still attribute the final address to the name the user
// wrote a rule against.
TEST(DnsObserverTest, CnameChainCollapsesOntoTheQuestionDomain) {
  DnsObserver observer;
  Feed(observer, MakeDnsResponse("2ip.ru",
                     {CnameRecord("edge.cdn.example"),
                         ARecord(198, 51, 100, 9)}));

  EXPECT_EQ(observer.LookupDomain(V4(198, 51, 100, 9)), "2ip.ru");
}

TEST(DnsObserverTest, UnknownAddressHasNoDomain) {
  DnsObserver observer;
  Feed(observer, MakeDnsResponse("2ip.ru", {ARecord(104, 21, 0, 1)}));

  EXPECT_TRUE(observer.LookupDomain(V4(8, 8, 8, 8)).empty());
}

TEST(DnsObserverTest, IgnoresQueriesAndNonDnsTraffic) {
  DnsObserver observer;
  // A query, not a response.
  Feed(observer, MakeDnsResponse("2ip.ru", {ARecord(104, 21, 0, 1)}, false));
  EXPECT_EQ(observer.Counters().mappings_recorded, 0u);

  // A TCP packet on port 443.
  std::vector<std::uint8_t> tcp(40, 0);
  tcp[0] = 0x45;
  tcp[9] = 6;
  Feed(observer, tcp);
  EXPECT_EQ(observer.Counters().responses_parsed, 0u);

  // Truncated garbage must not read out of bounds.
  std::vector<std::uint8_t> tiny(4, 0);
  tiny[0] = 0x45;
  Feed(observer, tiny);
  EXPECT_EQ(observer.Counters().responses_parsed, 0u);
}

TEST(DnsObserverTest, LastAnswerWinsForAReusedAddress) {
  DnsObserver observer;
  Feed(observer, MakeDnsResponse("first.example", {ARecord(203, 0, 113, 1)}));
  ASSERT_EQ(observer.LookupDomain(V4(203, 0, 113, 1)), "first.example");

  Feed(observer, MakeDnsResponse("second.example", {ARecord(203, 0, 113, 1)}));
  EXPECT_EQ(observer.LookupDomain(V4(203, 0, 113, 1)), "second.example");
}

TEST(DnsObserverTest, MappingsExpireWithTheirTtl) {
  DnsObserverConfiguration config;
  config.min_ttl = std::chrono::seconds(0);
  config.max_ttl = std::chrono::seconds(3600);
  DnsObserver observer(config);

  Feed(observer, MakeDnsResponse("short.example", {ARecord(203, 0, 113, 5, 0)}));
  // A zero TTL is already expired, so the address cannot be attributed.
  EXPECT_TRUE(observer.LookupDomain(V4(203, 0, 113, 5)).empty());
  EXPECT_EQ(observer.ExpireOutdated(std::chrono::steady_clock::now()), 1u);
  EXPECT_EQ(observer.Counters().entries, 0u);
}

TEST(DnsObserverTest, ShortTtlIsClampedUpSoTheMappingSurvivesConnectSetup) {
  DnsObserverConfiguration config;
  config.min_ttl = std::chrono::seconds(30);
  DnsObserver observer(config);

  // A one-second TTL would otherwise be gone before the SYN arrives.
  Feed(observer, MakeDnsResponse("2ip.ru", {ARecord(104, 21, 0, 1, 1)}));
  EXPECT_EQ(observer.LookupDomain(V4(104, 21, 0, 1)), "2ip.ru");
  EXPECT_EQ(observer.ExpireOutdated(std::chrono::steady_clock::now()), 0u);
}

TEST(DnsObserverTest, LongTtlIsClampedDown) {
  DnsObserverConfiguration config;
  config.max_ttl = std::chrono::seconds(60);
  DnsObserver observer(config);

  Feed(observer, MakeDnsResponse("2ip.ru", {ARecord(104, 21, 0, 1, 604800)}));
  EXPECT_EQ(observer.LookupDomain(V4(104, 21, 0, 1)), "2ip.ru");
  EXPECT_EQ(
      observer.ExpireOutdated(
          std::chrono::steady_clock::now() + std::chrono::seconds(61)),
      1u);
}

TEST(DnsObserverTest, MapGrowthIsBounded) {
  DnsObserverConfiguration config;
  config.max_entries = 16;
  DnsObserver observer(config);

  for (int i = 0; i < 200; ++i) {
    Feed(observer,
        MakeDnsResponse("host.example",
            {ARecord(203, 0, static_cast<std::uint8_t>(i / 256),
                static_cast<std::uint8_t>(i % 256))}));
  }
  EXPECT_LE(observer.Counters().entries, 16u);
  EXPECT_GT(observer.Counters().evictions, 0u);
}

// The observer is the classifier's attribution source; this is the seam.
TEST(DnsObserverTest, DrivesClassifierAttribution) {
  DnsObserver observer;
  StaticDomainPolicy policy(RouteAction::fptn_l4);
  policy.AddRule("2ip.ru", RouteAction::direct);
  FlowClassifier classifier(ClassifierConfiguration{}, policy, observer);

  std::vector<std::uint8_t> syn(24, 0);
  syn[0] = 0x45;
  syn[9] = 6;
  syn[12] = 10;
  syn[13] = 8;
  syn[15] = 2;
  syn[16] = 104;
  syn[17] = 21;
  syn[19] = 1;
  syn[20] = 0xC3;
  syn[21] = 0x50;  // sport 50000
  syn[22] = 0x01;
  syn[23] = 0xBB;  // dport 443
  const PacketLease lease{
      syn.data(), static_cast<std::uint32_t>(syn.size()), 4, nullptr, nullptr};

  // Before the DNS answer is seen there is no name, so it tunnels.
  EXPECT_EQ(classifier.Classify(lease), RouteAction::fptn_l4);

  DnsObserver fresh_observer;
  FlowClassifier fresh(ClassifierConfiguration{}, policy, fresh_observer);
  Feed(fresh_observer, MakeDnsResponse("2ip.ru", {ARecord(104, 21, 0, 1)}));
  EXPECT_EQ(fresh.Classify(lease), RouteAction::direct);
}

}  // namespace
