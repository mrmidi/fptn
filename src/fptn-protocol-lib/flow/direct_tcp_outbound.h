/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <unordered_map>
#include <vector>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "fptn-protocol-lib/tunnel/flow_interfaces.h"

namespace fptn::tunnel::flow {

class DirectTcpOutbound final : public ITcpOutbound {
 public:
  static constexpr std::size_t kMaxQueuedBytes = 256 * 1024;
  static constexpr std::size_t kWritableLowWaterBytes = 64 * 1024;
  static constexpr std::size_t kReadBufferSize = 16 * 1024;

  explicit DirectTcpOutbound(boost::asio::any_io_executor executor);
  ~DirectTcpOutbound() override;

  DirectTcpOutbound(const DirectTcpOutbound&) = delete;
  DirectTcpOutbound& operator=(const DirectTcpOutbound&) = delete;

  void Open(FlowMetadata metadata, ITcpOutboundSink& sink) override;
  OutboundAdmission Write(FlowId flow, BufferSequence data) override;
  void Finish(FlowId flow) override;
  void Reset(FlowId flow) override;
  void StackWindowOpen(FlowId flow) override;

  void Stop() noexcept;
  std::uint64_t ActiveFlows() const noexcept {
    return active_flows_.load(std::memory_order_relaxed);
  }

 private:
  struct FlowState {
    explicit FlowState(const boost::asio::any_io_executor& executor)
        : socket(executor) {}

    FlowId id = 0;
    ITcpOutboundSink* sink = nullptr;
    boost::asio::ip::tcp::socket socket;
    std::deque<std::vector<std::uint8_t>> pending_writes;
    std::size_t queued_bytes = 0;
    std::vector<std::uint8_t> held_read;
    std::array<std::uint8_t, kReadBufferSize> rx_buffer{};
    bool connected = false;
    bool writing = false;
    bool tx_shutdown_requested = false;
    bool rx_eof = false;
    bool read_scheduled = false;
    bool closed = false;
  };

  FlowState* Find(FlowId flow) noexcept;
  void OnConnect(FlowId flow, const boost::system::error_code& ec);
  void StartWrite(FlowId flow);
  void OnWriteDone(FlowId flow, const boost::system::error_code& ec);
  void StartRead(FlowState& state);
  void OnRead(FlowId flow, const boost::system::error_code& ec,
      std::size_t length);
  bool DeliverHeldRead(FlowState& state);
  void CloseFlow(FlowId flow) noexcept;

  boost::asio::any_io_executor executor_;
  std::unordered_map<FlowId, std::unique_ptr<FlowState>> flows_;
  std::atomic<std::uint64_t> active_flows_{0};
  bool stopping_ = false;
};

}  // namespace fptn::tunnel::flow
