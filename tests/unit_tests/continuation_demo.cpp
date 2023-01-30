// Copyright (c) 2023, The Monero Project

//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "common/expect.h"

#include <gtest/gtest.h>

#include <future>
#include <iostream>
#include <memory>
#include <queue>

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
class ThreadPool
{
public:
    void add_task(std::packaged_task<void()> new_task)
    {
        m_pending_tasks.push(std::move(new_task));
    }

    bool try_run_next_task()
    {
        // check if there are any tasks
        if (m_pending_tasks.size() == 0)
            return false;

        // run the oldest task
        auto task_to_run{std::move(m_pending_tasks.front())};
        m_pending_tasks.pop();
        task_to_run();

        return true;
    }

private:
    std::queue<std::packaged_task<void()>> m_pending_tasks;
};
//-------------------------------------------------------------------------------------------------------------------
// the thread pool itself should not be exposed, otherwise someone could move the pool and cause issues
//-------------------------------------------------------------------------------------------------------------------
namespace detail
{
static ThreadPool& get_demo_threadpool()
{
    static ThreadPool threadpool{};
    return threadpool;
}
} //namespace detail
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void add_task_to_demo_threadpool(std::packaged_task<void()> new_task)
{
    detail::get_demo_threadpool().add_task(std::move(new_task));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename T>
static void add_task_to_demo_threadpool(T&& new_task)
{
    add_task_to_demo_threadpool(static_cast<std::packaged_task<void()>>(std::forward<T>(new_task)));
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool try_run_next_task_demo_threadpool()
{
    return detail::get_demo_threadpool().try_run_next_task();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void print_int(const int i)
{
    std::cerr << "print int: " << i << '\n';
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void add_int(const int x, int &i_inout)
{
    i_inout += x;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename I, typename T>
static auto initialize_future_task(I&& initial_value, T&& task)
{
    return std::packaged_task<decltype(task(std::declval<I>()))()>{
            [
                l_val  = std::forward<I>(initial_value),
                l_task = std::forward<T>(task)
            ] ()
            {
                return l_task(std::move(l_val));
            }
        };
}
//-------------------------------------------------------------------------------------------------------------------
// unary case
//-------------------------------------------------------------------------------------------------------------------
template <typename S, typename A>
static auto build_task_chain(S, A&& this_task)
{
    return std::forward<A>(this_task);
}
//-------------------------------------------------------------------------------------------------------------------
// fold into task 'a' its continuation 'the rest of the task chain'
//-------------------------------------------------------------------------------------------------------------------
template <typename S, typename A, typename... Types>
static auto build_task_chain(S scheduler, A&& this_task, Types&&... continuation_tasks)
{
    return
        [
            l_scheduler = scheduler,
            l_this_task = std::forward<A>(this_task),
            l_next_task = build_task_chain(scheduler, std::forward<Types>(continuation_tasks)...)
        ] (auto&& val)
        {
            // this task's job
            auto this_task_result = l_this_task(std::forward<decltype(val)>(val));

            // connect the next task to this task
            auto continuation = initialize_future_task(
                    std::forward<decltype(this_task_result)>(this_task_result),
                    std::move(l_next_task)
                );

            // save continuatin's result
            auto continuation_future = continuation.get_future();

            // submit the continuation task to the threadpool
            l_scheduler(std::move(continuation));

            // return the continuation's future
            return continuation_future;
        };
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename R>
static R unwrap_futures_chain(R&& future_result)
{
    return std::forward<R>(future_result);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename R, typename T>
static expect<R> unwrap_futures_chain(std::future<T>&& future)
{
    try { return unwrap_futures_chain<R>(future.get());   }
    catch (std::error_code e) { return e;                 }
    catch (...)               { return std::error_code{}; }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(continuation_demo, basic)
{
    // set up the basic task sequence in reverse order
    int val{10};
    int addor{5};
    // task 1: print
    // task 2: add 5
    // task 3: print
    auto task3 =
        [](const int val)
        {
            print_int(val);
        };
    auto task2 =
        [
            addor     = std::move(addor),
            next_task = std::move(task3)
        ] (int val)
        {
            // this task's job
            add_int(addor, val);

            // connect the next task to this task
            auto continuation =
                [
                    val  = std::move(val),
                    task = std::move(next_task)
                ] ()
                {
                    task(val);
                };

            // submit the next task
            add_task_to_demo_threadpool(std::move(continuation));
        };
    auto task1 =
        [
            val       = std::move(val),
            next_task = std::move(task2)
        ] ()
        {
            // this task's job
            print_int(val);

            // connect the next task to this task
            auto continuation =
                [
                    val  = std::move(val),
                    task = std::move(next_task)
                ] ()
                {
                    task(val);
                };

            // submit the next task
            add_task_to_demo_threadpool(std::move(continuation));
        };

    // submit the head of the sequence to the threadpool
    add_task_to_demo_threadpool(std::move(task1));

    // run tasks to completion
    int num_tasks_completed{0};
    while (try_run_next_task_demo_threadpool())
    {
        ++num_tasks_completed;
        std::cerr << "completed task #" << num_tasks_completed << '\n';
    }
}
//-------------------------------------------------------------------------------------------------------------------
TEST(continuation_demo, basic_ergonomic_autorun)
{
    // prepare scheduler
    auto scheduler =
        [](auto&& task)
        {
            task();
        };

    // set up the basic task sequence in reverse order
    int val{10};
    int addor{5};
    // task 1: print
    // task 2: add 5
    // task 3: print
    auto job1 =
        [](int val) -> int
        {
            print_int(val);
            return val;
        };
    auto job2 =
        [
            addor = std::move(addor)
        ] (int val) -> int
        {
            add_int(addor, val);
            return val;
        };
    auto job3 =
        [](int val) -> int
        {
            print_int(val);
            return val;
        };

    // build task chain
    auto task_chain = initialize_future_task(
            std::move(val),
            build_task_chain(
                    scheduler,
                    std::move(job1),
                    std::move(job2),
                    std::move(job3)
                )
        );

    // save the chain future result
    auto task_chain_future = task_chain.get_future();

    // submit the task chain
    scheduler(std::move(task_chain));

    // extract final result
    const expect<int> final_result = unwrap_futures_chain<int>(std::move(task_chain_future));
    EXPECT_TRUE(final_result);
    std::cerr << "final result: " << final_result.value() << '\n';
}
//-------------------------------------------------------------------------------------------------------------------
TEST(continuation_demo, basic_ergonomic_threadpool)
{
    // prepare scheduler
    auto scheduler =
        [](auto&& task)
        {
            add_task_to_demo_threadpool(std::forward<decltype(task)>(task));
        };

    // set up the basic task sequence in reverse order
    int val{10};
    int addor{5};
    // task 1: print
    // task 2: add 5
    // task 3: print
    auto job1 =
        [](int val) -> int
        {
            print_int(val);
            return val;
        };
    auto job2 =
        [
            addor = std::move(addor)
        ] (int val) -> int
        {
            add_int(addor, val);
            return val;
        };
    auto job3 =
        [](int val) -> int
        {
            print_int(val);
            return val;
        };

    // build task chain
    auto task_chain = initialize_future_task(
            std::move(val),
            build_task_chain(
                    scheduler,
                    std::move(job1),
                    std::move(job2),
                    std::move(job3)
                )
        );

    // save the chain future result
    auto task_chain_future = task_chain.get_future();

    // submit the task chain
    scheduler(std::move(task_chain));

    // run tasks to completion
    int num_tasks_completed{0};
    while (try_run_next_task_demo_threadpool())
    {
        ++num_tasks_completed;
        std::cerr << "completed task #" << num_tasks_completed << '\n';
    }

    // extract final result
    const expect<int> final_result = unwrap_futures_chain<int>(std::move(task_chain_future));
    EXPECT_TRUE(final_result);
    std::cerr << "final result: " << final_result.value() << '\n';
}
//-------------------------------------------------------------------------------------------------------------------
