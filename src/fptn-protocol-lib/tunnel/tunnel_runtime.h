/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <thread>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

namespace fptn::tunnel {

class TunnelRuntime final {
 public:
  TunnelRuntime();
  ~TunnelRuntime();

  TunnelRuntime(const TunnelRuntime&) = delete;
  TunnelRuntime& operator=(const TunnelRuntime&) = delete;

  void Start();
  void Stop() noexcept;

  boost::asio::any_io_executor Executor() { return ioc_.get_executor(); }

 private:
  boost::asio::io_context ioc_;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type>
      work_;
  std::thread thread_;
  bool running_ = false;
};

}  // namespace fptn::tunnel
