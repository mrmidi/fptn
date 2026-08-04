/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <memory>
#include <unordered_map>
#include <vector>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/udp.hpp>

#include "fptn-protocol-lib/tunnel/flow_interfaces.h"

namespace fptn::tunnel::flow {

class DirectUdpOutbound final : public IUdpOutbound {
 public:
  static constexpr std::size_t kMaxQueuedBytes = 256 * 1024;
  static constexpr std::size_t kReadBufferSize = 64 * 1024;

  explicit DirectUdpOutbound(boost::asio::any_io_executor executor);
  ~DirectUdpOutbound() override;

  DirectUdpOutbound(const DirectUdpOutbound&) = delete;
  DirectUdpOutbound& operator=(const DirectUdpOutbound&) = delete;

  void Open(FlowMetadata metadata, IUdpOutboundSink& sink) override;
  OutboundAdmission Send(FlowId flow, BufferView payload) override;
  void Reset(FlowId flow) override;

  void Stop() noexcept;
  std::uint64_t ActiveFlows() const noexcept {
    return active_flows_.load(std::memory_order_relaxed);
  }

 private:
  struct FlowState {
    explicit FlowState(const boost::asio::any_io_executor& executor)
        : socket(executor) {}

    FlowId id = 0;
    IUdpOutboundSink* sink = nullptr;
    boost::asio::ip::udp::socket socket;
    std::deque<std::vector<std::uint8_t>> pending_sends;
    std::size_t queued_bytes = 0;
    std::vector<std::uint8_t> rx_buffer;
    bool sending = false;
    bool receive_scheduled = false;
    bool closed = false;
  };

  FlowState* Find(FlowId flow) noexcept;
  void StartSend(FlowId flow);
  void OnSendDone(FlowId flow, const boost::system::error_code& ec);
  void StartReceive(FlowState& state);
  void OnReceive(FlowId flow, const boost::system::error_code& ec,
      std::size_t length);
  void CloseFlow(FlowId flow) noexcept;

  boost::asio::any_io_executor executor_;
  std::unordered_map<FlowId, std::unique_ptr<FlowState>> flows_;
  std::atomic<std::uint64_t> active_flows_{0};
  bool stopping_ = false;
};

}  // namespace fptn::tunnel::flow
