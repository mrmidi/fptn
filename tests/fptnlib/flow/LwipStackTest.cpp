#include <gtest/gtest.h>

#include <chrono>
#include <memory>

#include "fptn-protocol-lib/flow/lwip_stack.h"

#include "fake_outbound.h"
#include "flow_test_support.h"

namespace {

using namespace fptn::tunnel;
using namespace fptn::tunnel::flow;
using namespace fptn::tunnel::flow::testing;

class LwipStackTest : public ::testing::Test {
 protected:
  void SetUp() override {
    stack_ = std::make_unique<LwipStack>(runtime_.Executor(),
        StackConfiguration{}, sink_, router_, outbound_, udp_outbound_,
        [this](OwnedPacketBatch batch) { collector_.Append(std::move(batch)); });
  }

  void TearDown() override {
    if (stack_) {
      stack_->Stop();
      stack_.reset();
    }
    // Every accepted lease must have been released exactly once by the
    // stack; rejected batches are released by the test in Inject().
    EXPECT_EQ(leases_.LiveLeases(), 0u);
  }

  template <typename Predicate>
  bool PollUntil(Predicate predicate,
      std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) {
        return true;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return predicate();
  }

  PacketInputResult Inject(const std::vector<std::uint8_t>& packet,
      std::uint8_t ip_version) {
    PacketLease lease = leases_.Make(packet, ip_version);
    const PacketLease batch[] = {lease};
    const PacketInputResult result = stack_->InputPackets(batch);
    if (result != PacketInputResult::accepted) {
      // Ownership stays with the caller on any non-accepted result.
      ReleasePacketLease(lease);
    }
    return result;
  }

  TestRuntime runtime_;
  RecordingSink sink_;
  TestRouter router_;
  FakeTcpOutbound outbound_;
  FakeUdpOutbound udp_outbound_;
  OutputCollector collector_;
  LeaseFactory leases_;
  std::unique_ptr<LwipStack> stack_;
};

TEST_F(LwipStackTest, LifecycleStartStop) {
  ASSERT_TRUE(stack_->Start().has_value());
  EXPECT_TRUE(stack_->IsRunning());
  EXPECT_FALSE(stack_->Start().has_value());
  stack_->Stop();
  EXPECT_FALSE(stack_->IsRunning());
  stack_->Stop();

  ASSERT_TRUE(stack_->Start().has_value());
  stack_->Stop();
  EXPECT_FALSE(stack_->IsRunning());
}

TEST_F(LwipStackTest, InputBeforeStartIsRejected) {
  const auto packet = MakeTcpV4(
      "10.8.0.2", "93.184.216.34", 50000, 443, 1000, 0, kFlagSyn);
  const PacketLease lease{packet.data(),
      static_cast<std::uint32_t>(packet.size()), 4, nullptr, nullptr};
  const PacketLease batch[] = {lease};
  EXPECT_EQ(stack_->InputPackets(batch), PacketInputResult::transport_stopped);
}

TEST_F(LwipStackTest, MalformedLeaseIsRejected) {
  ASSERT_TRUE(stack_->Start().has_value());

  const std::uint8_t bytes[] = {0x45, 0x00};
  const PacketLease null_lease{nullptr, 20, 4, nullptr, nullptr};
  const PacketLease zero_lease{bytes, 0, 4, nullptr, nullptr};
  const PacketLease bad_version{bytes, 2, 9, nullptr, nullptr};

  const PacketLease null_batch[] = {null_lease};
  EXPECT_EQ(stack_->InputPackets(null_batch),
      PacketInputResult::invalid_packet);
  const PacketLease zero_batch[] = {zero_lease};
  EXPECT_EQ(stack_->InputPackets(zero_batch),
      PacketInputResult::invalid_packet);
  const PacketLease bad_batch[] = {bad_version};
  EXPECT_EQ(stack_->InputPackets(bad_batch),
      PacketInputResult::invalid_packet);
}

TEST_F(LwipStackTest, IngressBudgetRejectsOversizedBatch) {
  StackConfiguration config;
  config.max_ingress_inflight_bytes = 32;
  auto bounded = std::make_unique<LwipStack>(runtime_.Executor(),
      std::move(config), sink_, router_, outbound_, udp_outbound_,
      [this](OwnedPacketBatch batch) { collector_.Append(std::move(batch)); });
  ASSERT_TRUE(bounded->Start().has_value());

  const auto packet = MakeTcpV4(
      "10.8.0.2", "93.184.216.34", 50000, 443, 1000, 0, kFlagSyn);
  const PacketLease lease{packet.data(),
      static_cast<std::uint32_t>(packet.size()), 4, nullptr, nullptr};
  const PacketLease batch[] = {lease};
  EXPECT_EQ(bounded->InputPackets(batch), PacketInputResult::queue_full);

  bounded->Stop();
}

TEST_F(LwipStackTest, Ipv4SynProducesSynAck) {
  ASSERT_TRUE(stack_->Start().has_value());

  const auto syn = MakeTcpV4(
      "10.8.0.2", "93.184.216.34", 50000, 443, 0x11223344, 0, kFlagSyn);
  EXPECT_EQ(Inject(syn, 4), PacketInputResult::accepted);
  ASSERT_TRUE(collector_.WaitForCount(1));

  const auto output = collector_.Snapshot();
  ASSERT_EQ(output.size(), 1u);
  const auto& data = output[0].data;
  EXPECT_EQ(output[0].ip_version, 4);
  ASSERT_GE(data.size(), 40u);
  EXPECT_EQ(data[0] >> 4, 4u);
  EXPECT_EQ(data[9], 6u);

  in_addr src;
  in_addr dst;
  std::memcpy(&src, data.data() + 12, 4);
  std::memcpy(&dst, data.data() + 16, 4);
  char src_text[INET_ADDRSTRLEN] = {};
  char dst_text[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &src, src_text, sizeof(src_text));
  inet_ntop(AF_INET, &dst, dst_text, sizeof(dst_text));
  EXPECT_STREQ(src_text, "93.184.216.34");
  EXPECT_STREQ(dst_text, "10.8.0.2");

  EXPECT_EQ(ReadPort(data, 20), 443u);
  EXPECT_EQ(ReadPort(data, 22), 50000u);
  const std::uint8_t flags = ReadFlags(data, 20);
  EXPECT_TRUE((flags & kFlagSyn) != 0);
  EXPECT_TRUE((flags & kFlagAck) != 0);
  EXPECT_EQ(ReadAck(data, 20), 0x11223344u + 1u);
}

TEST_F(LwipStackTest, Ipv6SynProducesSynAck) {
  ASSERT_TRUE(stack_->Start().has_value());

  const auto syn = MakeTcpV6("fd00::2", "2606:2800:220:1::1", 50000, 443,
      0x11223344, 0, kFlagSyn);
  EXPECT_EQ(Inject(syn, 6), PacketInputResult::accepted);
  ASSERT_TRUE(collector_.WaitForCount(1));

  const auto output = collector_.Snapshot();
  ASSERT_EQ(output.size(), 1u);
  const auto& data = output[0].data;
  EXPECT_EQ(output[0].ip_version, 6);
  ASSERT_GE(data.size(), 60u);
  EXPECT_EQ(data[0] >> 4, 6u);
  EXPECT_EQ(data[6], 6u);

  const std::uint8_t flags = ReadFlags(data, 40);
  EXPECT_TRUE((flags & kFlagSyn) != 0);
  EXPECT_TRUE((flags & kFlagAck) != 0);
  EXPECT_EQ(ReadPort(data, 40), 443u);
  EXPECT_EQ(ReadPort(data, 42), 50000u);
  EXPECT_EQ(ReadAck(data, 40), 0x11223344u + 1u);
}

TEST_F(LwipStackTest, GarbagePacketIsDroppedWithoutOutput) {
  ASSERT_TRUE(stack_->Start().has_value());

  std::vector<std::uint8_t> garbage(64, 0xAB);
  garbage[0] = 0x45;
  garbage[2] = 0x00;
  garbage[3] = 64;
  EXPECT_EQ(Inject(garbage, 4), PacketInputResult::accepted);

  EXPECT_FALSE(collector_.WaitForCount(1, std::chrono::milliseconds(300)));
  EXPECT_TRUE(stack_->IsRunning());
}

TEST_F(LwipStackTest, OrdinaryTcpIsZeroCopyIngress) {
  ASSERT_TRUE(stack_->Start().has_value());

  const auto syn = MakeTcpV4(
      "10.8.0.2", "93.184.216.34", 50000, 443, 0x11223344, 0, kFlagSyn);
  EXPECT_EQ(Inject(syn, 4), PacketInputResult::accepted);
  ASSERT_TRUE(collector_.WaitForCount(1));

  const auto& counters = stack_->counters();
  EXPECT_EQ(counters.input_packets.load(), 1u);
  EXPECT_EQ(counters.input_bytes.load(), syn.size());
  // Lease bytes are borrowed through a custom PBUF_REF pbuf: no copies.
  EXPECT_EQ(counters.ingress_zero_copy_packets.load(), 1u);
  EXPECT_EQ(counters.ingress_zero_copy_bytes.load(), syn.size());
  EXPECT_EQ(counters.ingress_copy_packets.load(), 0u);
  EXPECT_EQ(counters.ingress_copy_bytes.load(), 0u);
  EXPECT_GE(counters.output_packets.load(), 1u);
}

TEST_F(LwipStackTest, WritableClassesTakeCopyFallback) {
  ASSERT_TRUE(stack_->Start().has_value());

  // ICMP echo (v4 and v6) is answered in place, and fragments feed the
  // reassembly paths that overwrite header storage: all must be copied.
  const auto icmp4 = MakeIcmpV4Echo("10.8.0.2", "93.184.216.34");
  EXPECT_EQ(Inject(icmp4, 4), PacketInputResult::accepted);
  const auto icmp6 = MakeIcmpV6Echo("fd00::2", "2606:2800:220:1::1");
  EXPECT_EQ(Inject(icmp6, 6), PacketInputResult::accepted);

  auto frag_mf = MakeTcpV4(
      "10.8.0.2", "93.184.216.34", 50000, 443, 1000, 0, kFlagAck);
  MarkV4MoreFragments(frag_mf);
  EXPECT_EQ(Inject(frag_mf, 4), PacketInputResult::accepted);

  auto frag_offset = MakeTcpV4(
      "10.8.0.2", "93.184.216.34", 50000, 443, 1000, 0, kFlagAck);
  MarkV4FragmentOffset(frag_offset);
  EXPECT_EQ(Inject(frag_offset, 4), PacketInputResult::accepted);

  const auto frag6 =
      MakeFragmentedTcpV6("fd00::2", "2606:2800:220:1::1", 50000, 443);
  EXPECT_EQ(Inject(frag6, 6), PacketInputResult::accepted);

  const std::uint64_t expected_bytes = icmp4.size() + icmp6.size() +
                                       frag_mf.size() + frag_offset.size() +
                                       frag6.size();
  const auto& counters = stack_->counters();
  ASSERT_TRUE(PollUntil([&] {
    return counters.ingress_copy_packets.load(std::memory_order_relaxed) >=
           5u;
  }));
  EXPECT_EQ(counters.ingress_copy_packets.load(), 5u);
  EXPECT_EQ(counters.ingress_copy_bytes.load(), expected_bytes);
  EXPECT_EQ(counters.ingress_zero_copy_packets.load(), 0u);
  // Copy fallback releases each lease immediately after copying.
  ASSERT_TRUE(PollUntil([&] { return leases_.LiveLeases() == 0u; }));
  EXPECT_EQ(leases_.ReleasedLeases(), 5u);
}

TEST_F(LwipStackTest, LeasePoolExhaustionFallsBackToCopy) {
  ASSERT_TRUE(stack_->Start().has_value());

  // Handshake a TCP flow, then backpressure it so every data segment's
  // borrowed pbuf stays retained. Past the bounded wrapper pool capacity
  // the stack must fall back to a counted copy instead of failing.
  const std::uint16_t dport = 443;
  const auto syn = MakeTcpV4(
      "10.8.0.2", "93.184.216.34", 50000, dport, 1000, 0, kFlagSyn);
  EXPECT_EQ(Inject(syn, 4), PacketInputResult::accepted);
  ASSERT_TRUE(collector_.WaitForCount(1));
  const auto synack = collector_.Snapshot().front();
  const std::uint32_t server_seq = ReadSeq(synack.data, 20) + 1;
  const auto ack = MakeTcpV4("10.8.0.2", "93.184.216.34", 50000, dport,
      1001, server_seq, kFlagAck);
  EXPECT_EQ(Inject(ack, 4), PacketInputResult::accepted);

  outbound_.SetRejectWrites(true);
  const std::vector<std::uint8_t> payload(16, 0x5A);
  std::uint32_t client_seq = 1001;
  const std::size_t total_segments = LwipStack::kIngressWrapperPoolCapacity + 8;
  for (std::size_t i = 0; i < total_segments; ++i) {
    const auto segment = MakeTcpV4("10.8.0.2", "93.184.216.34", 50000,
        dport, client_seq, server_seq, kFlagAck, payload);
    client_seq += static_cast<std::uint32_t>(payload.size());
    ASSERT_EQ(Inject(segment, 4), PacketInputResult::accepted);
  }

  const auto& counters = stack_->counters();
  ASSERT_TRUE(PollUntil([&] {
    return counters.lease_pool_exhaustions.load(std::memory_order_relaxed) >=
           1u;
  }));
  EXPECT_GE(counters.ingress_copy_packets.load(), 1u);
  // Retained zero-copy leases stay live until teardown frees the pbufs.
  EXPECT_GT(leases_.LiveLeases(), 0u);

  // Stop must release every retained lease.
  stack_->Stop();
  EXPECT_EQ(leases_.LiveLeases(), 0u);
}

TEST_F(LwipStackTest, StopAfterAcceptedBatchReleasesLeases) {
  ASSERT_TRUE(stack_->Start().has_value());

  // Accept a batch, then stop before asserting anything else: the posted
  // ingress handler either ingests (and teardown frees) or drops and
  // releases. Either way every lease must be gone after Stop returns.
  for (std::uint16_t port = 50000; port < 50010; ++port) {
    const auto syn = MakeTcpV4(
        "10.8.0.2", "93.184.216.34", port, 443, 1000, 0, kFlagSyn);
    EXPECT_EQ(Inject(syn, 4), PacketInputResult::accepted);
  }
  stack_->Stop();
  EXPECT_EQ(leases_.LiveLeases(), 0u);
  EXPECT_EQ(leases_.ReleasedLeases(), 10u);
  // Re-arm so TearDown's second Stop() stays a no-op.
  stack_.reset();
}

}  // namespace
