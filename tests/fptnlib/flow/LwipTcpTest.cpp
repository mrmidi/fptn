#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <type_traits>

#include <boost/asio/post.hpp>

#include "fptn-protocol-lib/flow/lwip_stack.h"

#include "fake_outbound.h"
#include "flow_test_support.h"

namespace {

using namespace fptn::tunnel;
using namespace fptn::tunnel::flow;
using namespace fptn::tunnel::flow::testing;

constexpr const char* kAppIp = "10.8.0.2";
constexpr const char* kDstIp = "93.184.216.34";
constexpr std::uint16_t kAppPort = 50000;
constexpr std::uint16_t kDstPort = 443;
constexpr std::uint32_t kClientIss = 0x11223344;

template <typename Predicate>
bool PollUntil(Predicate predicate,
    std::chrono::milliseconds timeout = std::chrono::seconds(3)) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return predicate();
}

class LwipTcpTest : public ::testing::Test {
 protected:
  void SetUp() override {
    stack_ = std::make_unique<LwipStack>(runtime_.Executor(),
        StackConfiguration{}, sink_, router_, outbound_, udp_outbound_,
        [this](OwnedPacketBatch batch) { collector_.Append(std::move(batch)); });
    ASSERT_TRUE(stack_->Start().has_value());
  }

  void TearDown() override {
    if (stack_) {
      stack_->Stop();
      stack_.reset();
    }
  }

  // Runs fn on the stack executor thread and blocks until it completes.
  // Sink/data-path methods must execute on the executor (lwIP is
  // single-threaded), mirroring how real outbounds invoke them.
  template <typename Fn>
  auto RunOnExecutor(Fn&& fn) {
    using Result = decltype(fn());
    if constexpr (std::is_void_v<Result>) {
      std::promise<void> promise;
      auto future = promise.get_future();
      boost::asio::post(runtime_.Executor(),
          [&promise, fn = std::forward<Fn>(fn)]() mutable {
            fn();
            promise.set_value();
          });
      future.get();
    } else {
      auto promise = std::make_shared<std::promise<Result>>();
      auto future = promise->get_future();
      boost::asio::post(runtime_.Executor(),
          [promise, fn = std::forward<Fn>(fn)]() mutable {
            promise->set_value(fn());
          });
      return future.get();
    }
  }

  PacketInputResult Inject(const std::vector<std::uint8_t>& packet) {
    const PacketLease lease{packet.data(),
        static_cast<std::uint32_t>(packet.size()), 4, nullptr, nullptr};
    const PacketLease batch[] = {lease};
    return stack_->InputPackets(batch);
  }

  const OwnedPacket* FindPacket(std::uint8_t required_flags,
      std::uint8_t prohibited_flags = 0) {
    packets_ = collector_.Snapshot();
    for (const auto& packet : packets_) {
      if (packet.ip_version != 4 || packet.data.size() < 40) {
        continue;
      }
      const std::uint8_t flags = ReadFlags(packet.data, 20);
      if ((flags & required_flags) == required_flags &&
          (flags & prohibited_flags) == 0) {
        return &packet;
      }
    }
    return nullptr;
  }

  bool DoHandshake(
      std::uint16_t app_port = kAppPort, std::uint32_t iss = kClientIss) {
    Inject(MakeTcpV4(
        kAppIp, kDstIp, app_port, kDstPort, iss, 0, kFlagSyn));

    bool got_synack = collector_.WaitFor(1,
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

    client_seq_ = iss + 1;
    Inject(MakeTcpV4(kAppIp, kDstIp, app_port, kDstPort, client_seq_,
        server_seq_, kFlagAck));

    return PollUntil([this] { return !outbound_.Opened().empty(); });
  }

  FlowId OpenedFlow() const {
    EXPECT_FALSE(outbound_.Opened().empty());
    return outbound_.Opened().front().metadata.id;
  }

  ITcpOutboundSink* OutboundSink() {
    EXPECT_FALSE(outbound_.Opened().empty());
    return outbound_.Opened().front().sink;
  }

  TestRuntime runtime_;
  RecordingSink sink_;
  TestRouter router_;
  FakeTcpOutbound outbound_;
  FakeUdpOutbound udp_outbound_;
  OutputCollector collector_;
  std::unique_ptr<LwipStack> stack_;
  std::vector<OwnedPacket> packets_;
  std::uint32_t client_seq_ = 0;
  std::uint32_t server_seq_ = 0;
};

TEST_F(LwipTcpTest, HandshakeOpensFlowAndRoutesDirect) {
  ASSERT_TRUE(DoHandshake());

  ASSERT_EQ(sink_.Opened().size(), 1u);
  const FlowMetadata metadata = sink_.Opened().front();
  EXPECT_EQ(metadata.protocol, TransportProtocol::tcp);
  EXPECT_EQ(metadata.source.address.to_string(), kAppIp);
  EXPECT_EQ(metadata.source.port, kAppPort);
  EXPECT_EQ(metadata.destination.address.to_string(), kDstIp);
  EXPECT_EQ(metadata.destination.port, kDstPort);

  ASSERT_EQ(outbound_.Opened().size(), 1u);
  EXPECT_EQ(outbound_.Opened().front().metadata.id, metadata.id);
  EXPECT_EQ(stack_->ActiveTcpFlows(), 1u);
}

TEST_F(LwipTcpTest, AppDataDeliveredToOutboundAndAcked) {
  ASSERT_TRUE(DoHandshake());

  const std::string payload = "hello";
  const std::vector<std::uint8_t> bytes(payload.begin(), payload.end());
  Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, kDstPort, client_seq_,
      server_seq_, kFlagAck, bytes));

  ASSERT_TRUE(PollUntil([this, &payload] {
    const auto written = outbound_.Written();
    return !written.empty() && written.front().flow == OpenedFlow() &&
           std::string(written.front().bytes.begin(),
               written.front().bytes.end()) == payload;
  }));

  const std::uint32_t expected_ack = client_seq_ +
      static_cast<std::uint32_t>(payload.size());
  ASSERT_TRUE(collector_.WaitFor(2,
      [expected_ack](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 && packet.data.size() >= 40 &&
              ReadFlags(packet.data, 20) == kFlagAck &&
              ReadAck(packet.data, 20) == expected_ack) {
            return true;
          }
        }
        return false;
      }));
}

TEST_F(LwipTcpTest, OutboundDataReachesApp) {
  ASSERT_TRUE(DoHandshake());

  const std::string payload = "world";
  const FlowId flow = OpenedFlow();
  OwnedBuffer data(payload.begin(), payload.end());
  const bool accepted = RunOnExecutor(
      [&] { return OutboundSink()->OnOutboundData(flow, data); });
  EXPECT_TRUE(accepted);
  EXPECT_TRUE(data.empty());

  ASSERT_TRUE(collector_.WaitFor(2,
      [&payload](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 &&
              packet.data.size() == 40 + payload.size() &&
              std::memcmp(packet.data.data() + 40, payload.data(),
                  payload.size()) == 0) {
            return true;
          }
        }
        return false;
      }));

  const auto output = collector_.Snapshot();
  const OwnedPacket* data_packet = nullptr;
  for (const auto& packet : output) {
    if (packet.data.size() == 40 + payload.size()) {
      data_packet = &packet;
      break;
    }
  }
  ASSERT_NE(data_packet, nullptr);
  EXPECT_EQ(ReadSeq(data_packet->data, 20), server_seq_);
  EXPECT_EQ(ReadAck(data_packet->data, 20), client_seq_);
  EXPECT_EQ(ReadPort(data_packet->data, 20), kDstPort);
  EXPECT_EQ(ReadPort(data_packet->data, 22), kAppPort);
}

TEST_F(LwipTcpTest, BackpressureHoldsDataUntilOutboundAdmits) {
  ASSERT_TRUE(DoHandshake());
  outbound_.SetRejectWrites(true);

  const std::string payload = "stall";
  const std::vector<std::uint8_t> bytes(payload.begin(), payload.end());
  Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, kDstPort, client_seq_,
      server_seq_, kFlagAck, bytes));

  EXPECT_FALSE(PollUntil([this] { return !outbound_.Written().empty(); },
      std::chrono::milliseconds(300)));
  EXPECT_GE(stack_->counters().tcp_backpressure_events.load(), 1u);

  outbound_.SetRejectWrites(false);
  RunOnExecutor([this] { OutboundSink()->OnOutboundWritable(OpenedFlow()); });

  ASSERT_TRUE(PollUntil([this, &payload] {
    const auto written = outbound_.Written();
    if (written.empty()) {
      return false;
    }
    return std::string(written.front().bytes.begin(),
               written.front().bytes.end()) == payload;
  }));

  const std::uint32_t data_ack = client_seq_ +
      static_cast<std::uint32_t>(payload.size());
  ASSERT_TRUE(collector_.WaitFor(2,
      [data_ack](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 && packet.data.size() >= 40 &&
              ReadAck(packet.data, 20) == data_ack) {
            return true;
          }
        }
        return false;
      }));
}

TEST_F(LwipTcpTest, AppFinPropagatesAndFlowCloses) {
  ASSERT_TRUE(DoHandshake());
  const FlowId flow = OpenedFlow();

  Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, kDstPort, client_seq_,
      server_seq_, kFlagFin | kFlagAck));

  ASSERT_TRUE(PollUntil([this, flow] {
    const auto finished = outbound_.Finished();
    return std::find(finished.begin(), finished.end(), flow) !=
        finished.end();
  }));

  const std::uint32_t fin_ack = client_seq_ + 1;
  ASSERT_TRUE(collector_.WaitFor(2,
      [fin_ack](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 && packet.data.size() >= 40 &&
              ReadAck(packet.data, 20) == fin_ack &&
              (ReadFlags(packet.data, 20) & kFlagRst) == 0) {
            return true;
          }
        }
        return false;
      }));

  RunOnExecutor([this, flow] { OutboundSink()->OnOutboundFinished(flow); });

  ASSERT_TRUE(collector_.WaitFor(3,
      [fin_ack](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 && packet.data.size() >= 40 &&
              (ReadFlags(packet.data, 20) & kFlagFin) != 0 &&
              ReadAck(packet.data, 20) == fin_ack) {
            return true;
          }
        }
        return false;
      }));

  ASSERT_TRUE(PollUntil([this] { return stack_->ActiveTcpFlows() == 0; }));
}

TEST_F(LwipTcpTest, OutboundResetProducesRstToApp) {
  ASSERT_TRUE(DoHandshake());
  const FlowId flow = OpenedFlow();
  ASSERT_EQ(stack_->ActiveTcpFlows(), 1u);

  RunOnExecutor(
      [this, flow] { OutboundSink()->OnOutboundReset(flow, FlowError::reset); });

  ASSERT_TRUE(collector_.WaitFor(2,
      [](const std::vector<OwnedPacket>& packets) {
        for (const auto& packet : packets) {
          if (packet.ip_version == 4 && packet.data.size() >= 40 &&
              (ReadFlags(packet.data, 20) & kFlagRst) != 0) {
            return true;
          }
        }
        return false;
      }));
  ASSERT_TRUE(PollUntil([this] { return stack_->ActiveTcpFlows() == 0; }));
  EXPECT_GE(stack_->counters().tcp_resets.load(), 1u);
}

// Review P0-1: Open() failing synchronously re-enters ResetTcp() during
// OnTcpAccept and erases the map-owned flow. The accept callback must not
// touch the freed flow state afterwards (ASan-verified) and must emit RST.
TEST_F(LwipTcpTest, SyncTcpOpenFailureDoesNotUseFreedFlow) {
  outbound_.SetFailOpen(true);

  Inject(MakeTcpV4(
      kAppIp, kDstIp, kAppPort, kDstPort, kClientIss, 0, kFlagSyn));
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
      }));
  Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, kDstPort, kClientIss + 1,
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
      }));
  ASSERT_TRUE(PollUntil([this] { return stack_->ActiveTcpFlows() == 0; }));
  EXPECT_TRUE(outbound_.Opened().empty());
  EXPECT_GE(stack_->counters().tcp_resets.load(), 1u);

  // The stack stays usable after the failed connection. Clear the collector
  // so the second handshake's SYN-ACK wait does not match the stale first
  // SYN-ACK (which would yield a wrong server seq).
  outbound_.SetFailOpen(false);
  collector_.Reset();
  ASSERT_TRUE(DoHandshake(kAppPort + 1, kClientIss + 0x1000));
  EXPECT_EQ(stack_->ActiveTcpFlows(), 1u);
}

namespace {

std::atomic<int> g_tcp_close_calls{0};
std::atomic<int> g_tcp_abort_calls{0};

err_t FailTcpClose(struct tcp_pcb*) {
  g_tcp_close_calls.fetch_add(1, std::memory_order_relaxed);
  return ERR_MEM;
}

void RecordTcpAbort(struct tcp_pcb* pcb) {
  g_tcp_abort_calls.fetch_add(1, std::memory_order_relaxed);
  // Run the real abort so the injected pcb actually leaves lwIP's global
  // pcb lists; otherwise repeated in-process tests see a live pcb whose
  // tuple matches the fixture and whose timers keep firing.
  tcp_abort(pcb);
}

}  // namespace

// Review P0-2: when tcp_close() fails (data still queued/unacked), the pcb
// is aborted and the enclosing lwIP callback must return ERR_ABRT. The
// behavioral proof is the abort counter plus flow teardown; returning
// ERR_OK instead would leave lwIP touching the freed pcb, which ASan
// catches.
TEST_F(LwipTcpTest, CloseFailureAbortsPcbAndReturnsErrAbrt) {
  g_tcp_close_calls.store(0);
  g_tcp_abort_calls.store(0);
  stack_->SetTcpApiForTesting(
      LwipTcpApi{.close = &FailTcpClose, .abort = &RecordTcpAbort});

  ASSERT_TRUE(DoHandshake());
  const FlowId flow = OpenedFlow();

  // Outbound finishes first (remote EOF) so the application FIN is the last
  // missing condition and triggers the close path.
  RunOnExecutor([this, flow] { OutboundSink()->OnOutboundFinished(flow); });

  Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, kDstPort, client_seq_,
      server_seq_, kFlagFin | kFlagAck));

  // Ingress is processed on the stack executor; wait for the close path.
  ASSERT_TRUE(PollUntil([] { return g_tcp_close_calls.load() >= 1; }));
  EXPECT_EQ(g_tcp_abort_calls.load(), 1);
  ASSERT_TRUE(PollUntil([this] { return stack_->ActiveTcpFlows() == 0; }));
  const auto completed = outbound_.Completed();
  EXPECT_NE(std::find(completed.begin(), completed.end(), flow),
      completed.end());
}

// Review P1-3: an application FIN arriving while lwIP still retains a
// backpressured pbuf must not forward Finish() to the outbound early; the
// retained bytes must be admitted first, then Finish follows.
TEST_F(LwipTcpTest, FinWaitsUntilRetainedDataIsAdmitted) {
  ASSERT_TRUE(DoHandshake());
  const FlowId flow = OpenedFlow();

  outbound_.SetRejectWrites(true);

  const std::string payload = "not lost";
  const std::vector<std::uint8_t> bytes(payload.begin(), payload.end());
  Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, kDstPort, client_seq_,
      server_seq_, kFlagAck, bytes));
  ASSERT_TRUE(PollUntil([this] {
    return stack_->counters().tcp_backpressure_events.load() >= 1;
  }));

  // FIN while the pbuf is retained: neither data nor Finish may reach the
  // outbound yet.
  Inject(MakeTcpV4(kAppIp, kDstIp, kAppPort, kDstPort,
      client_seq_ + static_cast<std::uint32_t>(bytes.size()), server_seq_,
      kFlagFin | kFlagAck));
  EXPECT_FALSE(PollUntil(
      [this] {
        return !outbound_.Written().empty() || !outbound_.Finished().empty();
      },
      std::chrono::milliseconds(300)));

  outbound_.SetRejectWrites(false);
  RunOnExecutor([this, flow] { OutboundSink()->OnOutboundWritable(flow); });

  ASSERT_TRUE(PollUntil([this, &payload] {
    const auto written = outbound_.Written();
    return !written.empty() &&
           std::string(written.front().bytes.begin(),
               written.front().bytes.end()) == payload;
  }));
  ASSERT_TRUE(PollUntil([this, flow] {
    const auto finished = outbound_.Finished();
    return std::find(finished.begin(), finished.end(), flow) !=
        finished.end();
  }));
}

TEST_F(LwipTcpTest, TeardownAbortsActiveFlows) {
  ASSERT_TRUE(DoHandshake());
  ASSERT_EQ(stack_->ActiveTcpFlows(), 1u);

  stack_->Stop();
  EXPECT_EQ(stack_->ActiveTcpFlows(), 0u);

  const auto syn = MakeTcpV4(
      kAppIp, kDstIp, kAppPort, kDstPort, kClientIss, 0, kFlagSyn);
  const PacketLease lease{syn.data(),
      static_cast<std::uint32_t>(syn.size()), 4, nullptr, nullptr};
  const PacketLease batch[] = {lease};
  EXPECT_EQ(stack_->InputPackets(batch), PacketInputResult::transport_stopped);
}

}  // namespace
