#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>

#include "fptn-protocol-lib/tunnel/flow_interfaces.h"
#include "fptn-protocol-lib/tunnel/flow_types.h"

namespace fptn::tunnel::flow::testing {

class FakeTcpOutbound final : public ITcpOutbound {
 public:
  struct OpenedFlow {
    FlowMetadata metadata;
    ITcpOutboundSink* sink = nullptr;
  };

  void Open(FlowMetadata metadata, ITcpOutboundSink& sink) override {
    opened_.push_back(OpenedFlow{metadata, &sink});
    if (auto_admit_open_) {
      sink.OnOutboundConnected(metadata.id);
    }
  }
  OutboundAdmission Write(FlowId flow, BufferSequence data) override {
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

  void Finish(FlowId flow) override { finished_.push_back(flow); }

  void Reset(FlowId flow) override { reset_.push_back(flow); }

  void StackWindowOpen(FlowId flow) override {
    window_open_.push_back(flow);
  }

  void SetRejectWrites(bool reject) { reject_writes_ = reject; }
  void SetClosed(bool closed) { closed_ = closed; }
  void SetAutoAdmitOpen(bool auto_admit) { auto_admit_open_ = auto_admit; }

  const std::vector<OpenedFlow>& Opened() const { return opened_; }
  const std::vector<FlowId>& Finished() const { return finished_; }
  const std::vector<FlowId>& Reset() const { return reset_; }
  const std::vector<FlowId>& WindowOpen() const { return window_open_; }

  struct WrittenData {
    FlowId flow;
    std::vector<std::uint8_t> bytes;
  };
  const std::vector<WrittenData>& Written() const { return written_; }

  void ClearWritten() { written_.clear(); }

 private:
  std::vector<OpenedFlow> opened_;
  std::vector<WrittenData> written_;
  std::vector<FlowId> finished_;
  std::vector<FlowId> reset_;
  std::vector<FlowId> window_open_;
  bool reject_writes_ = false;
  bool closed_ = false;
  bool auto_admit_open_ = false;
};

class RecordingSink final : public IFlowEventSink {
 public:
  void OnTcpOpen(FlowMetadata metadata) override {
    opened_.push_back(metadata);
  }
  void OnTcpData(FlowId, OwnedBuffer) override {}
  void OnTcpHalfClose(FlowId) override {}
  void OnTcpReset(FlowId, FlowError) override {}
  void OnUdpDatagram(FlowMetadata, OwnedBuffer) override {}

  const std::vector<FlowMetadata>& Opened() const { return opened_; }

 private:
  std::vector<FlowMetadata> opened_;
};

}  // namespace fptn::tunnel::flow::testing
