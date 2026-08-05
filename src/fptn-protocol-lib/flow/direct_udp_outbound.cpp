/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/flow/direct_udp_outbound.h"

#include <new>
#include <utility>

namespace fptn::tunnel::flow {

DirectUdpOutbound::DirectUdpOutbound(boost::asio::any_io_executor executor)
    : executor_(std::move(executor)) {}

DirectUdpOutbound::~DirectUdpOutbound() { Stop(); }

void DirectUdpOutbound::Open(FlowMetadata metadata, IUdpOutboundSink& sink) {
  if (stopping_) {
    sink.OnUdpReset(metadata.id, FlowError::shutdown);
    return;
  }

  const FlowId flow = metadata.id;
  auto report_failure = [this, &sink, flow](FlowError error) {
    // Report asynchronously: Open() runs inside the stack's UDP accept
    // dispatch, and the generated lwIP pcb must survive that dispatch.
    try {
      boost::asio::post(executor_, [&sink, flow, error] {
        sink.OnUdpReset(flow, error);
      });
    // NOLINTNEXTLINE(bugprone-empty-catch): allocation failure drops the reset.
    } catch (const std::bad_alloc&) {
      // Post can only fail from allocation failure during shutdown; the
      // flow is dropped without a reset notification.
    }
  };

  auto state = std::make_unique<FlowState>(executor_);
  state->id = metadata.id;
  state->sink = &sink;
  state->rx_buffer.resize(kReadBufferSize);

  boost::system::error_code ec;
  const auto protocol = metadata.destination.address.is_v4()
                            ? boost::asio::ip::udp::v4()
                            : boost::asio::ip::udp::v6();
  state->socket.open(protocol, ec);
  if (ec) {
    report_failure(FlowError::outbound_failure);
    return;
  }

  const boost::asio::ip::udp::endpoint endpoint{
      metadata.destination.address, metadata.destination.port};
  state->socket.connect(endpoint, ec);
  if (ec) {
    boost::system::error_code close_ec;
    state->socket.close(close_ec);
    report_failure(FlowError::outbound_failure);
    return;
  }

  flows_.emplace(flow, std::move(state));
  active_flows_.fetch_add(1, std::memory_order_relaxed);

  FlowState* registered = flows_[flow].get();
  StartReceive(*registered);
}

OutboundAdmission DirectUdpOutbound::Send(FlowId flow, BufferView payload) {
  FlowState* state = Find(flow);
  if (state == nullptr || state->closed || stopping_ || payload.size == 0) {
    return OutboundAdmission::flow_closed;
  }
  if (state->queued_bytes + payload.size > kMaxQueuedBytes) {
    return OutboundAdmission::queue_full;
  }

  state->pending_sends.emplace_back(
      payload.data, payload.data + payload.size);
  state->queued_bytes += payload.size;

  if (!state->sending) {
    StartSend(flow);
  }
  return OutboundAdmission::accepted;
}

void DirectUdpOutbound::StartSend(FlowId flow) {
  FlowState* state = Find(flow);
  if (state == nullptr || state->sending || state->pending_sends.empty()) {
    return;
  }
  state->sending = true;
  state->socket.async_send(
      boost::asio::buffer(state->pending_sends.front()),
      [this, flow](const boost::system::error_code& ec, std::size_t) {
        OnSendDone(flow, ec);
      });
}

void DirectUdpOutbound::OnSendDone(
    FlowId flow, const boost::system::error_code& ec) {
  FlowState* state = Find(flow);
  if (state == nullptr) {
    return;
  }
  state->sending = false;
  if (ec) {
    IUdpOutboundSink* sink = state->sink;
    CloseFlow(flow);
    sink->OnUdpReset(flow, FlowError::outbound_failure);
    return;
  }
  state->queued_bytes -= state->pending_sends.front().size();
  state->pending_sends.pop_front();
  if (!state->pending_sends.empty()) {
    StartSend(flow);
  }
}

void DirectUdpOutbound::StartReceive(FlowState& state) {
  if (state.receive_scheduled || state.closed || stopping_) {
    return;
  }
  state.receive_scheduled = true;
  const FlowId flow = state.id;
  state.socket.async_receive(boost::asio::buffer(state.rx_buffer),
      [this, flow](const boost::system::error_code& ec, std::size_t length) {
        OnReceive(flow, ec, length);
      });
}

void DirectUdpOutbound::OnReceive(FlowId flow,
    const boost::system::error_code& ec, std::size_t length) {
  FlowState* state = Find(flow);
  if (state == nullptr) {
    return;
  }
  state->receive_scheduled = false;
  if (ec) {
    IUdpOutboundSink* sink = state->sink;
    CloseFlow(flow);
    sink->OnUdpReset(flow, FlowError::outbound_failure);
    return;
  }
  if (length > 0) {
    OwnedBuffer payload(
        state->rx_buffer.data(), state->rx_buffer.data() + length);
    state->sink->OnUdpDatagramReceived(flow, std::move(payload));
  }
  FlowState* after = Find(flow);
  if (after != nullptr) {
    StartReceive(*after);
  }
}

void DirectUdpOutbound::Reset(FlowId flow) {
  FlowState* state = Find(flow);
  if (state == nullptr) {
    return;
  }
  CloseFlow(flow);
}

DirectUdpOutbound::FlowState* DirectUdpOutbound::Find(FlowId flow) noexcept {
  const auto it = flows_.find(flow);
  return it == flows_.end() ? nullptr : it->second.get();
}

void DirectUdpOutbound::CloseFlow(FlowId flow) noexcept {
  const auto it = flows_.find(flow);
  if (it == flows_.end()) {
    return;
  }
  FlowState* state = it->second.get();
  state->closed = true;
  boost::system::error_code ec;
  state->socket.close(ec);
  flows_.erase(it);
  active_flows_.fetch_sub(1, std::memory_order_relaxed);
}

void DirectUdpOutbound::Stop() noexcept {
  stopping_ = true;
  while (!flows_.empty()) {
    CloseFlow(flows_.begin()->second->id);
  }
}

}  // namespace fptn::tunnel::flow
