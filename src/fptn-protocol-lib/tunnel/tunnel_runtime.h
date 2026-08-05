/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

#pragma once

#include <future>
#include <thread>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

namespace fptn::tunnel {

// One-shot runtime: after Stop() the io_context cannot be restarted and
// Start() returns false. Owners must create a new engine per session.
class TunnelRuntime final {
 public:
  TunnelRuntime();
  ~TunnelRuntime();

  TunnelRuntime(const TunnelRuntime&) = delete;
  TunnelRuntime& operator=(const TunnelRuntime&) = delete;

  bool Start();
  void Stop() noexcept;

  bool IsRunning() const noexcept { return running_; }
  bool IsStoppedEver() const noexcept { return stopped_ever_; }
  bool IsCurrentThread() const noexcept {
    return thread_id_ != std::thread::id{} &&
           std::this_thread::get_id() == thread_id_;
  }
  std::thread::id ThreadId() const noexcept { return thread_id_; }
  boost::asio::any_io_executor Executor() { return ioc_.get_executor(); }

 private:
  boost::asio::io_context ioc_;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type>
      work_;
  std::thread thread_;
  std::thread::id thread_id_{};
  bool running_ = false;
  bool stopped_ever_ = false;
};

}  // namespace fptn::tunnel
