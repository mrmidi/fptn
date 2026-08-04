/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <array>
#include <cstddef>

#include <lwip/pbuf.h>

#include "fptn-protocol-lib/tunnel/flow_types.h"

namespace fptn::tunnel::flow {

class PbufBufferSequence {
 public:
  static constexpr std::size_t kMaxSegments = 32;
  static constexpr std::size_t kDefaultMaxBytes = 64 * 1024;

  PbufBufferSequence(struct pbuf* chain,
      std::size_t max_bytes = kDefaultMaxBytes) noexcept {
    std::size_t remaining = max_bytes;
    for (struct pbuf* segment = chain;
         segment != nullptr && count_ < kMaxSegments && remaining > 0;
         segment = segment->next) {
      const std::size_t take =
          segment->len < remaining ? segment->len : remaining;
      if (take == 0) {
        continue;
      }
      buffers_[count_++] = BufferView{
          static_cast<const std::uint8_t*>(segment->payload), take};
      bytes_ += take;
      remaining -= take;
    }
  }

  const BufferView* begin() const noexcept { return buffers_.data(); }
  const BufferView* end() const noexcept { return buffers_.data() + count_; }
  BufferSequence View() const noexcept {
    return BufferSequence{buffers_.data(), buffers_.data() + count_};
  }
  std::size_t segment_count() const noexcept { return count_; }
  std::size_t size_bytes() const noexcept { return bytes_; }

 private:
  std::array<BufferView, kMaxSegments> buffers_{};
  std::size_t count_ = 0;
  std::size_t bytes_ = 0;
};

}  // namespace fptn::tunnel::flow
