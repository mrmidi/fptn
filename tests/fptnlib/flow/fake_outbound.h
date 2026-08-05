#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>

#include "fptn-protocol-lib/tunnel/flow_interfaces.h"
#include "fptn-protocol-lib/tunnel/flow_types.h"

namespace fptn::tunnel::flow::testing {

// Test doubles are driven by the stack on its executor thread while the test
// thread inspects them, so all recorded state is mutex-guarded and accessors
// return snapshots.
class FakeTcpOutbound final : public ITcpOutbound {
 public:
  struct OpenedFlow {
    FlowMetadata metadata;
    ITcpOutboundSink* sink = nullptr;
  };
  struct WrittenData {
    FlowId flow;
    std::vector<std::uint8_t> bytes;
  };

  void Open(FlowMetadata metadata, ITcpOutboundSink& sink) override {
    {
      std::lock_guard lock(mutex_);
      opened_.push_back(OpenedFlow{metadata, &sink});
    }
    if (auto_admit_open_) {
      sink.OnOutboundConnected(metadata.id);
    }
  }
  OutboundAdmission Write(FlowId flow, BufferSequence data) override {
    std::lock_guard lock(mutex_);
    if (reject_writes_) {
      return OutboundAdmission::queue_full;
    }
    if (closed_) {
      return OutboundAdmission::flow_closed;
    }
    std::vector<std::uint8_t> bytes;
    for (const auto& view : data) {
      bytes.insert(bytes.end(), view.data, view.data + view.size);
    }
    written_.push_back(WrittenData{flow, std::move(bytes)});
    return OutboundAdmission::accepted;
  }

  void Finish(FlowId flow) override {
    std::lock_guard lock(mutex_);
    finished_.push_back(flow);
  }

  void Reset(FlowId flow) override {
    std::lock_guard lock(mutex_);
    reset_.push_back(flow);
  }

  void StackWindowOpen(FlowId flow) override {
    std::lock_guard lock(mutex_);
    window_open_.push_back(flow);
  }

  void Complete(FlowId flow) override {
    std::lock_guard lock(mutex_);
    completed_.push_back(flow);
  }

  void SetRejectWrites(bool reject) {
    std::lock_guard lock(mutex_);
    reject_writes_ = reject;
  }
  void SetClosed(bool closed) {
    std::lock_guard lock(mutex_);
    closed_ = closed;
  }
  void SetAutoAdmitOpen(bool auto_admit) {
    std::lock_guard lock(mutex_);
    auto_admit_open_ = auto_admit;
  }

  std::vector<OpenedFlow> Opened() const {
    std::lock_guard lock(mutex_);
    return opened_;
  }
  std::vector<FlowId> Finished() const {
    std::lock_guard lock(mutex_);
    return finished_;
  }
  std::vector<FlowId> Reset() const {
    std::lock_guard lock(mutex_);
    return reset_;
  }
  std::vector<FlowId> WindowOpen() const {
    std::lock_guard lock(mutex_);
    return window_open_;
  }
  std::vector<FlowId> Completed() const {
    std::lock_guard lock(mutex_);
    return completed_;
  }
  std::vector<WrittenData> Written() const {
    std::lock_guard lock(mutex_);
    return written_;
  }

  void ClearWritten() {
    std::lock_guard lock(mutex_);
    written_.clear();
  }

 private:
  mutable std::mutex mutex_;
  std::vector<OpenedFlow> opened_;
  std::vector<WrittenData> written_;
  std::vector<FlowId> finished_;
  std::vector<FlowId> reset_;
  std::vector<FlowId> window_open_;
  std::vector<FlowId> completed_;
  bool reject_writes_ = false;
  bool closed_ = false;
  bool auto_admit_open_ = false;
};

class FakeUdpOutbound final : public IUdpOutbound {
 public:
  struct SentDatagram {
    FlowId flow;
    std::vector<std::uint8_t> bytes;
  };

  void Open(FlowMetadata metadata, IUdpOutboundSink& sink) override {
    if (fail_open_) {
      // Synchronous failure inside the stack's accept dispatch: exercises
      // the abandon-to-rejected path.
      sink.OnUdpReset(metadata.id, FlowError::outbound_failure);
      return;
    }
    std::lock_guard lock(mutex_);
    opened_.push_back(metadata);
    last_sink_ = &sink;
  }

  OutboundAdmission Send(FlowId flow, BufferView payload) override {
    std::lock_guard lock(mutex_);
    if (reject_sends_) {
      return OutboundAdmission::queue_full;
    }
    sent_.push_back(
        SentDatagram{flow,
            std::vector<std::uint8_t>(payload.data,
                payload.data + payload.size)});
    return OutboundAdmission::accepted;
  }

  void Reset(FlowId flow) override {
    std::lock_guard lock(mutex_);
    reset_.push_back(flow);
  }

  void SetRejectSends(bool reject) {
    std::lock_guard lock(mutex_);
    reject_sends_ = reject;
  }
  void SetFailOpen(bool fail) {
    std::lock_guard lock(mutex_);
    fail_open_ = fail;
  }

  std::vector<FlowMetadata> Opened() const {
    std::lock_guard lock(mutex_);
    return opened_;
  }
  std::vector<FlowId> Reset() const {
    std::lock_guard lock(mutex_);
    return reset_;
  }
  IUdpOutboundSink* LastSink() const {
    std::lock_guard lock(mutex_);
    return last_sink_;
  }
  std::vector<SentDatagram> Sent() const {
    std::lock_guard lock(mutex_);
    return sent_;
  }

 private:
  mutable std::mutex mutex_;
  std::vector<FlowMetadata> opened_;
  std::vector<SentDatagram> sent_;
  std::vector<FlowId> reset_;
  IUdpOutboundSink* last_sink_ = nullptr;
  bool reject_sends_ = false;
  bool fail_open_ = false;
};

class RecordingSink final : public IFlowEventSink {
 public:
  struct UdpDatagram {
    FlowMetadata metadata;
    OwnedBuffer payload;
  };

  void OnTcpOpen(FlowMetadata metadata) override {
    std::lock_guard lock(mutex_);
    opened_.push_back(metadata);
  }
  void OnTcpData(FlowId, OwnedBuffer) override {}
  void OnTcpHalfClose(FlowId) override {}
  void OnTcpReset(FlowId, FlowError) override {}
  void OnUdpDatagram(FlowMetadata metadata, OwnedBuffer payload) override {
    std::lock_guard lock(mutex_);
    udp_datagrams_.push_back(UdpDatagram{metadata, std::move(payload)});
  }

  std::vector<FlowMetadata> Opened() const {
    std::lock_guard lock(mutex_);
    return opened_;
  }
  std::vector<UdpDatagram> UdpDatagrams() const {
    std::lock_guard lock(mutex_);
    return udp_datagrams_;
  }

 private:
  mutable std::mutex mutex_;
  std::vector<FlowMetadata> opened_;
  std::vector<UdpDatagram> udp_datagrams_;
};

}  // namespace fptn::tunnel::flow::testing
