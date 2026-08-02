/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <thread>
#include <vector>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

namespace fptn::protocol::https {

// Shared io_context that every ApiClient operation runs on.
//
// Each coroutine owns its socket exclusively and shares no state with the
// others, so the worker threads need no strand.
class IoRuntime final {
 public:
  static IoRuntime& Instance();

  boost::asio::io_context& Context() noexcept { return ioc_; }

  IoRuntime(const IoRuntime&) = delete;
  IoRuntime& operator=(const IoRuntime&) = delete;
  IoRuntime(IoRuntime&&) = delete;
  IoRuntime& operator=(IoRuntime&&) = delete;

 private:
  IoRuntime();
  ~IoRuntime() = default;

  boost::asio::io_context ioc_;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type>
      work_guard_;
  std::vector<std::thread> threads_;
};

}  // namespace fptn::protocol::https
