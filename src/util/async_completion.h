// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_UTIL_ASYNC_COMPLETION_H
#define BITCOIN_UTIL_ASYNC_COMPLETION_H
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/associated_executor.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <atomic>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <variant>

namespace util {
/** Bridge an owned callback to Asio. Completion is posted, never resumed on a
 * commit/subscriber thread. Exactly-once claiming also handles initiation which
 * retains a callback and then throws: late delivery cannot resume a dead frame.
 * The executor stays alive through delivery. Cancellation does not undo work
 * already accepted by the node; its owned completion is still drained.
 */
template <typename T = void, typename Start>
boost::asio::awaitable<T> AwaitCompletion(
    boost::asio::any_io_executor executor, Start start) {
    using Value = std::conditional_t<std::is_void_v<T>, std::monostate, T>;
    auto token = boost::asio::use_awaitable;
    auto value = co_await boost::asio::async_initiate<
        decltype(token), void(std::exception_ptr, Value)>(
        [executor, start = std::move(start)](auto handler) mutable {
            using Handler = decltype(handler);
            struct State {
                std::atomic<bool> claimed{false};
                std::optional<Handler> handler;
                boost::asio::executor_work_guard<boost::asio::any_io_executor> work;
                State(Handler h, boost::asio::any_io_executor ex)
                    : handler(std::move(h)), work(ex) {}
            };
            // Preserve the caller's strand, not merely its underlying pool.
            boost::asio::any_io_executor resume_executor =
                boost::asio::get_associated_executor(handler, executor);
            auto state = std::make_shared<State>(std::move(handler), resume_executor);
            auto complete = [state, resume_executor](std::exception_ptr error,
                                               Value result) {
                if (state->claimed.exchange(true)) return;
                boost::asio::post(resume_executor,
                    [state, error, result = std::move(result)]() mutable {
                        auto handler = std::move(*state->handler);
                        state->handler.reset();
                        state->work.reset();
                        std::move(handler)(error, std::move(result));
                    });
            };
            // An unstranded executor may resume on another thread before
            // initiation returns. Move the starter off its coroutine frame
            // before exposing completion, so its callable stays alive locally.
            auto begin = std::move(start);
            try {
                begin(complete);
            } catch (...) {
                complete(std::current_exception(), Value{});
            }
        }, token);
    if constexpr (!std::is_void_v<T>) co_return std::move(value);
}
} // namespace util
#endif // BITCOIN_UTIL_ASYNC_COMPLETION_H
