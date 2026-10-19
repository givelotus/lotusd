// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHRONIK_NATIVE_TRANSPORT_QUERY_POOL_H
#define CHRONIK_NATIVE_TRANSPORT_QUERY_POOL_H

#include <chronik/native/http.h>

#include <boost/asio/associated_executor.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

#include <functional>
#include <memory>

namespace chronik::native {

/**
 * Fixed pool of threads running blocking Chronik work (HTTP handlers, WS
 * subscription handling), so transport io threads never block (design §3.4).
 */
class QueryPool {
public:
    using executor_type = boost::asio::thread_pool::executor_type;

    explicit QueryPool(size_t num_threads = DefaultThreads());
    ~QueryPool();
    QueryPool(const QueryPool &) = delete;
    QueryPool &operator=(const QueryPool &) = delete;

    /** min(8, max(1, hardware_concurrency / 2)) */
    static size_t DefaultThreads();

    executor_type GetExecutor() { return m_pool.get_executor(); }
    /** A strand on the pool: posted work runs serialized, in order. */
    boost::asio::strand<executor_type> MakeStrand() {
        return boost::asio::make_strand(m_pool.get_executor());
    }
    void Post(std::function<void()> fn) {
        boost::asio::post(m_pool, std::move(fn));
    }
    /** Stop accepting work and join (pending work is abandoned). */
    void Stop();
    /** Wait for queued work to finish, then join. */
    void Join();
    size_t NumThreads() const { return m_num_threads; }

private:
    size_t m_num_threads;
    boost::asio::thread_pool m_pool;
};

/**
 * Run router.Handle(req) on the pool and deliver the response to the
 * completion handler on its associated executor (e.g. an io strand or a
 * coroutine's executor). Usable with callbacks or boost::asio::use_awaitable:
 *
 *   HttpResponse resp = co_await AsyncHandle(pool, router, std::move(req),
 *                                            boost::asio::use_awaitable);
 */
template <typename CompletionToken>
auto AsyncHandle(QueryPool &pool, const Router &router, HttpRequest req,
                 CompletionToken &&token) {
    return boost::asio::async_initiate<CompletionToken, void(HttpResponse)>(
        [&pool, &router](auto handler, HttpRequest request) {
            auto work = boost::asio::make_work_guard(
                boost::asio::get_associated_executor(handler));
            // asio::post, not Post(std::function): handlers are move-only
            boost::asio::post(pool.GetExecutor(), [&router,
                                                   request = std::move(request),
                       handler = std::move(handler),
                       work = std::move(work)]() mutable {
                HttpResponse resp = router.Handle(request);
                auto ex = work.get_executor();
                boost::asio::dispatch(
                    ex, [handler = std::move(handler),
                         resp = std::move(resp)]() mutable {
                        std::move(handler)(std::move(resp));
                    });
                work.reset();
            });
        },
        token, std::move(req));
}

} // namespace chronik::native

#endif // CHRONIK_NATIVE_TRANSPORT_QUERY_POOL_H
