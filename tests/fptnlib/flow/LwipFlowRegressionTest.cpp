#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio/post.hpp>

#include "fptn-protocol-lib/flow/direct_tcp_outbound.h"
#include "fptn-protocol-lib/flow/lwip_stack.h"
#include "fptn-protocol-lib/tunnel/flow_proxy_data_plane.h"
#include "fptn-protocol-lib/tunnel/tunnel_engine.h"
#include "fptn-protocol-lib/tunnel/tunnel_runtime.h"

#include "fake_outbound.h"
#include "flow_test_support.h"
#include "posix_echo_server.h"

namespace {

using namespace fptn::tunnel;
using namespace fptn::tunnel::flow;
using namespace fptn::tunnel::flow::testing;

constexpr const char* kAppIp = "10.8.0.2";
constexpr const char* kDstIp = "127.0.0.1";
constexpr std::uint16_t kAppPort = 50000;
constexpr std::uint32_t kClientIss = 0x30000001;

template <typename Predicate>
bool PollUntil(Predicate predicate,
    std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return predicate();
}

struct BlockingRouter final : IFlowRouter {
  RouteAction Match(const FlowMetadata&) override {
    return RouteAction::reject;
  }
};

// Review case 1: aborting from the accept callback must return ERR_ABRT so
// tcp_input stops touching the freed pcb (verified behaviorally: RST out,
// no hang, no corruption).
class BlockedRouteRegressionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    stack_ = std::make_unique<LwipStack>(runtime_.Executor(),
        StackConfiguration{}, sink_, router_, tcp_outbound_, udp_outbound_,
        [this](OwnedPacketBatchView batch) { collector_.Append(batch); });
    ASSERT_TRUE(stack_->Start().has_value());
  }

  void TearDown() override {
    if (stack_) {
      stack_->Stop();
      stack_.reset();
    }
  }

  PacketInputResult Inject(const std::vector<std::uint8_t>& packet) {
    // Must own the bytes: ingress is posted to the executor and zero-copy
    // ingress borrows the lease well after this call returns, while callers
    // pass temporaries.
    PacketLease lease = leases_.Make(packet, 4);
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
  BlockingRouter router_;
  FakeTcpOutbound tcp_outbound_;
  FakeUdpOutbound udp_outbound_;
  OutputCollector collector_;
  LeaseFactory leases_;
  std::unique_ptr<LwipStack> stack_;
};

TEST_F(BlockedRouteRegressionTest, TcpBlockedRouteAbortsCleanly) {
  // The route check runs in the accept callback, which lwIP invokes only
  // when the handshake completes (SYN_RCVD -> ESTABLISHED on the 3rd ACK).
  Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, 443, kClientIss, 0, kFlagSyn));

  std::uint32_t server_seq = 0;
  ASSERT_TRUE(collector_.WaitFor(1,
      [&server_seq](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 && packet.data.size() >= 40 &&
              (ReadFlags(packet.data, 20) & kFlagSyn) != 0) {
            server_seq = ReadSeq(packet.data, 20) + 1;
            return true;
          }
        }
        return false;
      },
      std::chrono::seconds(5)));

  Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, 443, kClientIss + 1,
      server_seq, kFlagAck));

  ASSERT_TRUE(collector_.WaitFor(2,
      [](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 && packet.data.size() >= 40 &&
              (ReadFlags(packet.data, 20) & kFlagRst) != 0) {
            return true;
          }
        }
        return false;
      },
      std::chrono::seconds(5)));

  EXPECT_TRUE(PollUntil([this] {
    return stack_->counters().active_tcp_flows.load() == 0;
  },
      std::chrono::seconds(5)));
  EXPECT_TRUE(tcp_outbound_.Opened().empty());

  // A second connection attempt on the same tuple is also rejected cleanly.
  Inject(MakeTcpV4(
      kAppIp, kDstIp, kAppPort, 443, kClientIss + 0x1000, 0, kFlagSyn));
  std::uint32_t server_seq2 = 0;
  ASSERT_TRUE(collector_.WaitFor(3,
      [&server_seq2](const std::vector<OwnedPacket>& packets) {
        std::size_t synacks = 0;
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 && packet.data.size() >= 40 &&
              (ReadFlags(packet.data, 20) & kFlagSyn) != 0) {
            ++synacks;
            server_seq2 = ReadSeq(packet.data, 20) + 1;
          }
        }
        return synacks >= 2;
      },
      std::chrono::seconds(5)));
  Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, 443, kClientIss + 0x1000 + 1,
      server_seq2, kFlagAck));

  ASSERT_TRUE(PollUntil([this] {
    std::size_t rsts = 0;
    for (const auto& packet : collector_.Snapshot()) {
      if (packet.ip_version == 4 && packet.data.size() >= 40 &&
          (ReadFlags(packet.data, 20) & kFlagRst) != 0) {
        ++rsts;
      }
    }
    return rsts >= 2;
  },
      std::chrono::seconds(5)));
  EXPECT_EQ(stack_->counters().active_tcp_flows.load(), 0u);
}

TEST_F(BlockedRouteRegressionTest, UdpBlockedRouteNeverRecreatesPcb) {
  const std::vector<std::uint8_t> payload = {'q'};
  Inject(MakeUdpV4(kAppIp, kDstIp, kAppPort, 53, payload));

  ASSERT_TRUE(PollUntil([this] {
    return stack_->counters().udp_drops.load() >= 1;
  },
      std::chrono::seconds(5)));
  EXPECT_EQ(stack_->counters().active_udp_flows.load(), 0u);

  // Repeated datagrams keep hitting the dropping pcb instead of looping
  // the fork's accept/recreate path.
  for (int i = 0; i < 8; ++i) {
    Inject(MakeUdpV4(kAppIp, kDstIp, kAppPort, 53, payload));
  }
  EXPECT_TRUE(PollUntil([this] {
    return stack_->counters().udp_drops.load() >= 9;
  },
      std::chrono::seconds(5)));
  EXPECT_EQ(stack_->counters().active_udp_flows.load(), 0u);
  EXPECT_TRUE(udp_outbound_.Opened().empty());
}

class UdpFailedOpenRegressionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    udp_outbound_.SetFailOpen(true);
    stack_ = std::make_unique<LwipStack>(runtime_.Executor(),
        StackConfiguration{}, sink_, router_, tcp_outbound_, udp_outbound_,
        [this](OwnedPacketBatchView batch) { collector_.Append(batch); });
    ASSERT_TRUE(stack_->Start().has_value());
  }

  void TearDown() override {
    if (stack_) {
      stack_->Stop();
      stack_.reset();
    }
  }

  PacketInputResult Inject(const std::vector<std::uint8_t>& packet) {
    // Must own the bytes: ingress is posted to the executor and zero-copy
    // ingress borrows the lease well after this call returns, while callers
    // pass temporaries.
    PacketLease lease = leases_.Make(packet, 4);
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
  FakeTcpOutbound tcp_outbound_;
  FakeUdpOutbound udp_outbound_;
  OutputCollector collector_;
  LeaseFactory leases_;
  std::unique_ptr<LwipStack> stack_;
};

// Review case 6 (second half): a synchronous outbound-open failure inside
// the UDP accept dispatch must not remove the generated pcb (which would
// loop the fork's accept/recreate path).
TEST_F(UdpFailedOpenRegressionTest, SyncOpenFailureDoesNotLoop) {
  const std::vector<std::uint8_t> payload = {'q'};
  for (int i = 0; i < 4; ++i) {
    Inject(MakeUdpV4(kAppIp, kDstIp, kAppPort + i, 53, payload));
  }

  EXPECT_TRUE(PollUntil([this] {
    return stack_->counters().udp_drops.load() >= 4;
  },
      std::chrono::seconds(5)));
  EXPECT_EQ(stack_->counters().active_udp_flows.load(), 0u);
  EXPECT_TRUE(udp_outbound_.Opened().empty());
}

class EngineRegressionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    TunnelConfiguration config;
    config.mode = DataPlaneMode::flow_proxy;
    config.flow.tun_ipv4 = kAppIp;
    config.l3.tun_ipv6 = "fd00::1";
    callbacks_.on_owned_packet_batch = [this](OwnedPacketBatchView batch) {
      collector_.Append(batch);
    };
    auto result = TunnelEngine::Create(config, callbacks_);
    ASSERT_TRUE(result.has_value());
    engine_ = std::move(*result);
    ASSERT_TRUE(engine_->Start().has_value());
  }

  void TearDown() override {
    if (engine_) {
      engine_->Stop();
      engine_.reset();
    }
  }

  PacketInputResult Inject(const std::vector<std::uint8_t>& packet,
      std::uint8_t ip_version = 4) {
    // Must own the bytes: ingress is posted to the executor and zero-copy
    // ingress borrows the lease well after this call returns, while callers
    // pass temporaries.
    PacketLease lease = leases_.Make(packet, ip_version);
    const PacketLease batch[] = {lease};
    const PacketInputResult result = engine_->InputPackets(batch);
    if (result != PacketInputResult::accepted) {
      // Ownership stays with the caller on any non-accepted result.
      ReleasePacketLease(lease);
    }
    return result;
  }

  bool Handshake(std::uint16_t dst_port) {
    Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, dst_port, kClientIss, 0,
        kFlagSyn));
    const bool got_synack = collector_.WaitFor(1,
        [this](const std::vector<OwnedPacket>& packets) {
          for (const auto& packet : packets) {
            if (packet.ip_version == 4 && packet.data.size() >= 40 &&
                (ReadFlags(packet.data, 20) & kFlagSyn) != 0) {
              server_seq_ = ReadSeq(packet.data, 20) + 1;
              return true;
            }
          }
          return false;
        });
    if (!got_synack) {
      return false;
    }
    client_seq_ = kClientIss + 1;
    server_acked_seq_ = server_seq_;
    Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, dst_port, client_seq_,
        server_seq_, kFlagAck));
    return true;
  }

  void SendData(std::uint16_t dst_port,
      const std::vector<std::uint8_t>& payload) {
    Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, dst_port, client_seq_,
        server_seq_, kFlagAck | 0x08, payload));
    client_seq_ += static_cast<std::uint32_t>(payload.size());
  }

  // Models the device ACKing data the stack delivered, so the stack's
  // congestion/send window drains and subsequent segments (e.g. FIN) can
  // transmit. Advances the acked watermark to the highest server byte seen.
  void AckServerData(std::uint16_t dst_port) {
    std::uint32_t highest_end = server_acked_seq_;
    for (const auto& packet : collector_.Snapshot()) {
      const auto& data = packet.data;
      if (packet.ip_version != 4 || data.size() < 40 ||
          ReadPort(data, 20) != dst_port || ReadPort(data, 22) != kAppPort) {
        continue;
      }
      const std::uint32_t seg_seq = ReadSeq(data, 20);
      const std::uint8_t flags = ReadFlags(data, 20);
      const std::size_t tcp_hdr =
          static_cast<std::size_t>((data[20 + 12] & 0xF0u) >> 4) * 4;
      const std::size_t payload_len =
          data.size() > 20 + tcp_hdr ? data.size() - 20 - tcp_hdr : 0;
      std::uint32_t seg_end =
          seg_seq + static_cast<std::uint32_t>(payload_len);
      if (flags & kFlagSyn) {
        ++seg_end;
      }
      if (flags & kFlagFin) {
        ++seg_end;
      }
      if (seg_end > highest_end) {
        highest_end = seg_end;
      }
    }
    if (highest_end > server_acked_seq_) {
      Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, dst_port, client_seq_,
          highest_end, kFlagAck));
      server_acked_seq_ = highest_end;
    }
  }

  TunnelCallbacks callbacks_;
  OutputCollector collector_;
  LeaseFactory leases_;
  std::unique_ptr<TunnelEngine> engine_;
  std::uint32_t client_seq_ = 0;
  std::uint32_t server_seq_ = 0;
  std::uint32_t server_acked_seq_ = 0;
};

// Review case 2: ingress admission must be drained by Stop; no posted
// handler may outlive the stack or touch the removed netif.
TEST_F(EngineRegressionTest, IngressRacingStopStaysSafe) {
  std::atomic<bool> stop_requested{false};
  std::atomic<std::uint64_t> injected{0};
  std::thread injector([&] {
    const auto packet = MakeUdpV4(kAppIp, kDstIp, kAppPort, 9, {'r'});
    while (!stop_requested.load(std::memory_order_acquire)) {
      const PacketLease lease{packet.data(),
          static_cast<std::uint32_t>(packet.size()), 4, nullptr, nullptr};
      const PacketLease batch[] = {lease};
      engine_->InputPackets(batch);
      injected.fetch_add(1, std::memory_order_relaxed);
    }
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  engine_->Stop();
  stop_requested.store(true, std::memory_order_release);
  injector.join();
  EXPECT_GT(injected.load(), 0u);
  engine_.reset();
}

// Review case 3: FIN right after queued data must not truncate the stream;
// the outbound may only shut its send side after flushing pending writes.
TEST_F(EngineRegressionTest, FinAfterQueuedDataDeliversEverything) {
  PosixEchoServer server;
  ASSERT_TRUE(server.Start());
  ASSERT_TRUE(Handshake(server.port()));
  ASSERT_TRUE(server.WaitForAccepted(std::chrono::seconds(5)));

  std::size_t total = 0;
  for (int i = 0; i < 3; ++i) {
    const std::vector<std::uint8_t> chunk(1000,
        static_cast<std::uint8_t>('a' + i));
    total += chunk.size();
    SendData(server.port(), chunk);
  }

  // The device ACKs the echoed data so the stack's send window drains and
  // the later FIN can transmit (otherwise unacked bytes pin the cwnd shut).
  ASSERT_TRUE(PollUntil([this, &server, total] {
    AckServerData(server.port());
    return server.LiveReceivedBytes() >= total;
  },
      std::chrono::seconds(10)));

  Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, server.port(), client_seq_,
      server_acked_seq_, kFlagFin | kFlagAck));
  client_seq_ += 1;

  ASSERT_TRUE(server.WaitForConnectionEof(total, std::chrono::seconds(10)))
      << "bytes=" << server.LastConnectionBytes()
      << " clean_eof=" << server.LastConnectionCleanEof();

  // The app side sees the FIN coming back after its own FIN was processed.
  ASSERT_TRUE(PollUntil([this, &server]() {
    AckServerData(server.port());
    for (const auto& packet : collector_.Snapshot()) {
      if (packet.ip_version == 4 && packet.data.size() >= 40 &&
          ReadPort(packet.data, 20) == server.port() &&
          (ReadFlags(packet.data, 20) & kFlagFin) != 0) {
        return true;
      }
    }
    return false;
  },
      std::chrono::seconds(10)));

  server.Stop();
}

// Review case 5: the engine is one-shot once its runtime has stopped.
TEST_F(EngineRegressionTest, StoppedEngineRejectsRestart) {
  engine_->Stop();
  auto second = engine_->Start();
  ASSERT_FALSE(second.has_value());
  EXPECT_EQ(second.error(), TunnelError::already_running);
  engine_.reset();
}

// Review case 4: clean completions must release outbound sockets; run many
// sequential connections and require active-flow counts to return to zero.
class ManyConnectionsRegressionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    runtime_.Start();
    const auto executor = runtime_.Executor();
    tcp_outbound_ = std::make_unique<DirectTcpOutbound>(executor);
    stack_ = std::make_unique<LwipStack>(executor, StackConfiguration{},
        sink_, router_, *tcp_outbound_, udp_outbound_,
        [this](OwnedPacketBatchView batch) { collector_.Append(batch); });
    stack_->SetExecutorThreadId(runtime_.ThreadId());
    ASSERT_TRUE(stack_->Start().has_value());
  }

  void TearDown() override {
    if (stack_) {
      stack_->Stop();
    }
    if (tcp_outbound_) {
      std::promise<void> done;
      auto future = done.get_future();
      boost::asio::post(runtime_.Executor(), [this, &done] {
        tcp_outbound_->Stop();
        done.set_value();
      });
      future.get();
    }
    // Join the runtime before freeing stack/outbound so no queued handler
    // (connect/read/timer) can touch them after destruction.
    runtime_.Stop();
    stack_.reset();
    tcp_outbound_.reset();
  }

  TunnelRuntime runtime_;
  RecordingSink sink_;
  TestRouter router_;
  FakeUdpOutbound udp_outbound_;
  OutputCollector collector_;
  LeaseFactory leases_;
  std::unique_ptr<DirectTcpOutbound> tcp_outbound_;
  std::unique_ptr<LwipStack> stack_;
};

TEST_F(ManyConnectionsRegressionTest, CleanConnectionsReleaseAllState) {
  PosixEchoServer server;
  ASSERT_TRUE(server.Start());

  constexpr int kConnections = 50;
  for (int i = 0; i < kConnections; ++i) {
    const std::uint16_t app_port =
        static_cast<std::uint16_t>(kAppPort + i);
    const std::uint32_t iss = kClientIss + i * 0x10000u;
    const std::uint64_t prev_opened = tcp_outbound_->OpenedTotal();

    collector_.Reset();
    // The lease must own its bytes: ingress is posted to the executor and
    // zero-copy ingress borrows them well after InputPackets returns.
    const PacketLease lease = leases_.Make(
        MakeTcpV4(kAppIp, kDstIp, app_port, server.port(), iss, 0, kFlagSyn),
        4);
    const PacketLease batch[] = {lease};
    ASSERT_EQ(stack_->InputPackets(batch), PacketInputResult::accepted);

    std::uint32_t server_seq = 0;
    ASSERT_TRUE(collector_.WaitFor(1,
        [&server_seq](const std::vector<OwnedPacket>& packets) {
          for (const auto& packet : packets) {
            if (packet.ip_version == 4 && packet.data.size() >= 40 &&
                (ReadFlags(packet.data, 20) & kFlagSyn) != 0) {
              server_seq = ReadSeq(packet.data, 20) + 1;
              return true;
            }
          }
          return false;
        },
        std::chrono::seconds(5)));

    std::uint32_t client_seq = iss + 1;
    auto inject = [&](std::uint8_t flags,
                      const std::vector<std::uint8_t>& payload) {
      const PacketLease l = leases_.Make(
          MakeTcpV4(kAppIp, kDstIp, app_port, server.port(), client_seq,
              server_seq, flags, payload),
          4);
      const PacketLease b[] = {l};
      ASSERT_EQ(stack_->InputPackets(b), PacketInputResult::accepted);
      client_seq += static_cast<std::uint32_t>(payload.size());
    };

    inject(kFlagAck, {});
    const std::vector<std::uint8_t> payload = {
        static_cast<std::uint8_t>(i), 'x'};
    inject(kFlagAck | 0x08, payload);
    inject(kFlagFin | kFlagAck, {});

    // Phase 1: this connection's outbound flow must have opened. Use the
    // monotonic open counter so a fast open->close cycle cannot be missed,
    // and a stale zero from the previous connection cannot pass spuriously.
    ASSERT_TRUE(PollUntil([this, prev_opened] {
      return tcp_outbound_->OpenedTotal() > prev_opened;
    },
        std::chrono::seconds(5)))
        << "connection " << i << " never opened";

    // Phase 2: both the stack flow and the outbound socket must be released.
    ASSERT_TRUE(PollUntil([this] {
      return stack_->counters().active_tcp_flows.load() == 0 &&
             tcp_outbound_->ActiveFlows() == 0;
    },
        std::chrono::seconds(5)))
        << "connection " << i << " stack_flows="
        << stack_->counters().active_tcp_flows.load() << " outbound_flows="
        << tcp_outbound_->ActiveFlows();
  }

  EXPECT_EQ(tcp_outbound_->ActiveFlows(), 0u);
  EXPECT_EQ(stack_->counters().active_tcp_flows.load(), 0u);

  server.Stop();
}

// Review case 6: a Stop() issued from the runtime thread (e.g. from a
// native packet callback) must be rejected WITHOUT clearing started_;
// otherwise the plane is logically stopped but physically running, and
// every later external Stop() becomes a no-op (unrecoverable half-running
// state). A later external Stop() must still perform full teardown.
class FlowProxyLifecycleTest : public ::testing::Test {
 protected:
  void SetUp() override {
    TunnelConfiguration config;
    config.mode = DataPlaneMode::flow_proxy;
    config.flow.tun_ipv4 = kAppIp;
    config.l3.tun_ipv6 = "fd00::1";
    plane_ = std::make_unique<FlowProxyDataPlane>(
        std::move(config), TunnelCallbacks{});
    ASSERT_TRUE(plane_->Start().has_value());
  }

  void TearDown() override {
    if (plane_) {
      plane_->Stop();
      plane_.reset();
    }
  }

  std::unique_ptr<FlowProxyDataPlane> plane_;
};

TEST_F(FlowProxyLifecycleTest, ReentrantStopDoesNotPoisonExternalTeardown) {
  std::promise<void> attempted;
  auto attempted_future = attempted.get_future();
  boost::asio::post(plane_->RuntimeExecutorForTesting(), [this, &attempted] {
    plane_->Stop();
    attempted.set_value();
  });
  ASSERT_EQ(attempted_future.wait_for(std::chrono::seconds(2)),
      std::future_status::ready);

  EXPECT_EQ(plane_->ReentrantStopAttempts(), 1u);
  // The reentrant attempt must not pretend teardown was complete.
  EXPECT_TRUE(plane_->IsStartedForTesting());

  std::future<void> external_stop =
      std::async(std::launch::async, [this] { plane_->Stop(); });
  ASSERT_EQ(external_stop.wait_for(std::chrono::seconds(5)),
      std::future_status::ready);

  EXPECT_FALSE(plane_->IsStartedForTesting());
  EXPECT_EQ(plane_->ActiveTcpFlowsForTesting(), 0u);
  EXPECT_EQ(plane_->ActiveUdpFlowsForTesting(), 0u);
}

}  // namespace
