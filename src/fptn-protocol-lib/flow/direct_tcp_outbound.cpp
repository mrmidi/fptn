/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#include "fptn-protocol-lib/flow/direct_tcp_outbound.h"

#include <utility>

#include <boost/asio/connect.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

namespace fptn::tunnel::flow {

DirectTcpOutbound::DirectTcpOutbound(boost::asio::any_io_executor executor)
    : executor_(std::move(executor)), rx_scratch_(kReadBufferSize) {}

DirectTcpOutbound::~DirectTcpOutbound() { Stop(); }

void DirectTcpOutbound::Open(FlowMetadata metadata, ITcpOutboundSink& sink) {
  if (stopping_) {
    sink.OnOutboundReset(metadata.id, FlowError::shutdown);
    return;
  }

  auto state = std::make_unique<FlowState>(executor_);
  state->id = metadata.id;
  state->sink = &sink;

  const FlowId flow = metadata.id;
  boost::system::error_code ec;
  if (metadata.destination.address.is_v4()) {
    state->socket.open(boost::asio::ip::tcp::v4(), ec);
  } else {
    state->socket.open(boost::asio::ip::tcp::v6(), ec);
  }
  if (ec) {
    sink.OnOutboundReset(flow, FlowError::outbound_failure);
    return;
  }

  flows_.emplace(flow, std::move(state));
  active_flows_.fetch_add(1, std::memory_order_relaxed);
  opened_total_.fetch_add(1, std::memory_order_relaxed);

  const boost::asio::ip::tcp::endpoint endpoint{
      metadata.destination.address, metadata.destination.port};
  flows_[flow]->socket.async_connect(endpoint,
      [this, flow](const boost::system::error_code& connect_ec) {
        OnConnect(flow, connect_ec);
      });
}

void DirectTcpOutbound::OnConnect(
    FlowId flow, const boost::system::error_code& ec) {
  FlowState* state = Find(flow);
  if (state == nullptr) {
    return;
  }
  if (ec) {
    ITcpOutboundSink* sink = state->sink;
    CloseFlow(flow);
    sink->OnOutboundReset(
        flow, ec == boost::asio::error::connection_refused
                  ? FlowError::refused
                  : FlowError::outbound_failure);
    return;
  }
  state->connected = true;
  // The read after async_wait is synchronous; non-blocking guarantees it can
  // never stall the executor thread on a spurious readability signal.
  boost::system::error_code mode_ec;
  state->socket.non_blocking(true, mode_ec);
  state->sink->OnOutboundConnected(flow);
  if (Find(flow) == nullptr) {
    return;
  }
  StartWrite(flow);
  FlowState* after_write = Find(flow);
  if (after_write == nullptr) {
    return;
  }
  MaybeShutdownSend(*after_write);
  after_write = Find(flow);
  if (after_write != nullptr && !after_write->rx_eof) {
    StartRead(*after_write);
  }
}

OutboundAdmission DirectTcpOutbound::Write(
    FlowId flow, BufferSequence data) {
  FlowState* state = Find(flow);
  if (state == nullptr || state->closed || stopping_) {
    return OutboundAdmission::flow_closed;
  }

  std::size_t total = 0;
  for (const auto& view : data) {
    total += view.size;
  }
  if (total == 0) {
    return OutboundAdmission::accepted;
  }
  if (state->queued_bytes + total > kMaxQueuedBytes) {
    return OutboundAdmission::queue_full;
  }

  std::vector<std::uint8_t> chunk;
  chunk.reserve(total);
  for (const auto& view : data) {
    chunk.insert(chunk.end(), view.data, view.data + view.size);
  }
  state->queued_bytes += total;
  state->pending_writes.push_back(std::move(chunk));

  if (state->connected && !state->writing) {
    StartWrite(flow);
  }
  return OutboundAdmission::accepted;
}

// StartWrite and OnWriteDone form an intentional asynchronous chain
// (each completion schedules the next chunk); it is bounded by the pending
// queue, not unbounded recursion.
// NOLINTBEGIN(misc-no-recursion)
void DirectTcpOutbound::StartWrite(FlowId flow) {
  FlowState* state = Find(flow);
  if (state == nullptr || state->writing || state->pending_writes.empty()) {
    return;
  }
  state->writing = true;
  boost::asio::async_write(state->socket,
      boost::asio::buffer(state->pending_writes.front()),
      [this, flow](const boost::system::error_code& ec, std::size_t) {
        OnWriteDone(flow, ec);
      });
}

void DirectTcpOutbound::OnWriteDone(
    FlowId flow, const boost::system::error_code& ec) {
  FlowState* state = Find(flow);
  if (state == nullptr) {
    return;
  }
  state->writing = false;
  if (ec) {
    ITcpOutboundSink* sink = state->sink;
    CloseFlow(flow);
    sink->OnOutboundReset(flow, FlowError::outbound_failure);
    return;
  }
  const std::size_t written = state->pending_writes.front().size();
  state->pending_writes.pop_front();
  state->queued_bytes -= written;

  if (!state->pending_writes.empty()) {
    StartWrite(flow);
    return;
  }
  if (state->complete_requested) {
    // Complete() was deferred while writes were in flight; all bytes are
    // written now, so the socket can close.
    CloseFlow(flow);
    return;
  }
  MaybeShutdownSend(*state);
  if (state->queued_bytes <= kWritableLowWaterBytes) {
    state->sink->OnOutboundWritable(flow);
  }
}
// NOLINTEND(misc-no-recursion)

void DirectTcpOutbound::MaybeShutdownSend(FlowState& state) {
  if (!state.connected || !state.tx_shutdown_requested ||
      state.tx_shutdown_done || state.writing ||
      !state.pending_writes.empty()) {
    return;
  }
  boost::system::error_code ec;
  state.socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
  state.tx_shutdown_done = true;
}

// Waits for readability instead of posting a buffered read, so no buffer is
// pinned per flow while the socket is idle; the read below fills the shared
// scratch synchronously on the executor thread.
void DirectTcpOutbound::StartRead(FlowState& state) {
  if (state.read_scheduled || state.rx_eof || state.closed || stopping_) {
    return;
  }
  state.read_scheduled = true;
  const FlowId flow = state.id;
  state.socket.async_wait(boost::asio::ip::tcp::socket::wait_read,
      [this, flow](const boost::system::error_code& ec) {
        OnReadable(flow, ec);
      });
}

void DirectTcpOutbound::OnReadable(
    FlowId flow, const boost::system::error_code& ec) {
  FlowState* state = Find(flow);
  if (state == nullptr) {
    return;
  }
  state->read_scheduled = false;

  if (ec) {
    ITcpOutboundSink* sink = state->sink;
    CloseFlow(flow);
    sink->OnOutboundReset(flow, FlowError::outbound_failure);
    return;
  }

  boost::system::error_code read_ec;
  const std::size_t length =
      state->socket.read_some(boost::asio::buffer(rx_scratch_), read_ec);
  if (read_ec == boost::asio::error::would_block ||
      read_ec == boost::asio::error::try_again) {
    // Spurious readability; wait again rather than tearing the flow down.
    StartRead(*state);
    return;
  }
  if (read_ec == boost::asio::error::eof) {
    state->rx_eof = true;
    state->sink->OnOutboundFinished(flow);
    return;
  }
  if (read_ec) {
    ITcpOutboundSink* sink = state->sink;
    CloseFlow(flow);
    sink->OnOutboundReset(flow, FlowError::outbound_failure);
    return;
  }

  state->held_read.assign(
      rx_scratch_.data(), rx_scratch_.data() + length);
  if (DeliverHeldRead(*state)) {
    StartRead(*state);
  }
}

bool DirectTcpOutbound::DeliverHeldRead(FlowState& state) {
  if (state.held_read.empty()) {
    return true;
  }
  OwnedBuffer data = std::move(state.held_read);
  state.held_read.clear();
  if (state.sink->OnOutboundData(state.id, data)) {
    return true;
  }
  state.held_read = std::move(data);
  return false;
}

void DirectTcpOutbound::Finish(FlowId flow) {
  FlowState* state = Find(flow);
  if (state == nullptr) {
    return;
  }
  state->tx_shutdown_requested = true;
  MaybeShutdownSend(*state);
}

void DirectTcpOutbound::Reset(FlowId flow) {
  FlowState* state = Find(flow);
  if (state == nullptr) {
    return;
  }
  CloseFlow(flow);
}

void DirectTcpOutbound::Complete(FlowId flow) {
  FlowState* state = Find(flow);
  if (state == nullptr) {
    return;
  }
  // Closing the socket now would cancel queued/in-flight writes and drop
  // bytes the stack already considers delivered. Defer until the write
  // chain drains (OnWriteDone honors complete_requested).
  if (state->writing || !state->pending_writes.empty()) {
    state->complete_requested = true;
    return;
  }
  CloseFlow(flow);
}

void DirectTcpOutbound::StackWindowOpen(FlowId flow) {
  FlowState* state = Find(flow);
  if (state == nullptr) {
    return;
  }
  if (!state->held_read.empty() && DeliverHeldRead(*state) &&
      !state->rx_eof) {
    StartRead(*state);
  }
}

DirectTcpOutbound::FlowState* DirectTcpOutbound::Find(FlowId flow) noexcept {
  const auto it = flows_.find(flow);
  return it == flows_.end() ? nullptr : it->second.get();
}

void DirectTcpOutbound::CloseFlow(FlowId flow) noexcept {
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

void DirectTcpOutbound::Stop() noexcept {
  stopping_ = true;
  while (!flows_.empty()) {
    CloseFlow(flows_.begin()->second->id);
  }
}

}  // namespace fptn::tunnel::flow
