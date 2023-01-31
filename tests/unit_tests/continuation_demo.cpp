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
static void mul_int(const int x, int &i_inout)
{
    i_inout *= x;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename I, typename T, typename R>
static auto initialize_future_task(I &&initial_value, T &&task, std::promise<R> promise)
{
    return
        [
            l_val     = std::forward<I>(initial_value),
            l_task    = std::forward<T>(task),
            l_promise = std::move(promise)
        ] () mutable -> void
        {
            l_task(std::move(l_val), std::move(l_promise));
        };
}
//-------------------------------------------------------------------------------------------------------------------
// end case: set the promise from the task result
//-------------------------------------------------------------------------------------------------------------------
template <typename R, typename S, typename A>
static auto build_task_tree(S, A &&this_task)
{
    return
        [
            l_task = std::forward<A>(this_task)
        ] (auto&& this_task_val, std::promise<R> promise) mutable -> void
        {
            try { promise.set_value(l_task(std::move(this_task_val))); }
            catch (...)
            {
                try { promise.set_exception(std::current_exception()); } catch (...) { /*can't do anything*/ }
            }
        };
}
//-------------------------------------------------------------------------------------------------------------------
// fold into task 'a' its continuation 'the rest of the task tree'
//-------------------------------------------------------------------------------------------------------------------
template <typename R, typename S, typename A, typename... Ts>
static auto build_task_tree(S scheduler, A &&this_task, Ts &&...continuation_tasks)
{
    return
        [
            l_scheduler = scheduler,
            l_this_task = std::forward<A>(this_task),
            l_next_task = build_task_tree<R>(scheduler, std::forward<Ts>(continuation_tasks)...)
        ] (auto&& this_task_val, std::promise<R> promise) mutable -> void
        {
            // this task's job
            auto this_task_result =
                [&]() -> expect<decltype(l_this_task(std::declval<decltype(this_task_val)>()))>
                {
                    try { return l_this_task(std::forward<decltype(this_task_val)>(this_task_val)); }
                    catch (...)
                    {
                        try { promise.set_exception(std::current_exception()); } catch (...) { /*can't do anything*/ }
                        return std::error_code{};
                    }
                }();

            // give up if this task failed
            if (!this_task_result)
                return;

            // pass the result of this task to the continuation
            auto continuation = initialize_future_task(
                    std::forward<typename decltype(this_task_result)::value_type>(std::move(this_task_result).value()),
                    std::move(l_next_task),
                    std::move(promise)
                );

            // submit the continuation task to the scheduler
            l_scheduler(std::move(continuation));
        };
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename R, typename S, typename I, typename... Ts>
static std::future<R> schedule_task_tree(S scheduler, I &&initial_value, Ts &&...tasks)
{
    // prepare result channel
    std::promise<R> result_promise;
    std::future<R> result_future{result_promise.get_future()};

    // build task tree
    auto task_tree_head = initialize_future_task(
            std::forward<I>(initial_value),
            build_task_tree<R>(scheduler, std::forward<Ts>(tasks)...),
            std::move(result_promise)
        );

    // schedule task tree
    scheduler(std::move(task_tree_head));

    // return future
    return result_future;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename R>
expect<R> unwrap_future(std::future<R> future)
{
    if (!future.valid())      { return std::error_code{};       }
    try                       { return std::move(future.get()); }
    catch (std::error_code e) { return e;                       }
    catch (...)               { return std::error_code{};       }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename S>
static auto basic_continuation_demo_test(S scheduler)
{
    // set up the basic task sequence in reverse order
    int initial_val{10};
    int add_five{5};
    int mul_three{3};
    int mul_ten{10};
    // task 1: print
    // task 2: add 5
    // task 3: print
    // task 4 SPLIT: divide in half for each branch
    //   task 4a-1: print    task 4b-1: print
    //   task 4a-2: mul10
    // task 4 JOIN: add together each branch
    // task 5 print
    auto job1 =
        [](int val) -> int
        {
            print_int(val);
            return val;
        };
    auto job2 =
        [
            addor = std::move(add_five)
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
    auto job4 =
        [
            multiplier = std::move(mul_three)
        ] (int val) -> int
        {
            mul_int(multiplier, val);
            return val;
        };
    auto job4_split =
        [] (int val) -> std::tuple<int, int>
        {
            return {val/2, val/2};
        };
    auto job4a_1 =
        [] (int val) -> int
        {
            print_int(val);
            return val;
        };
    auto job4a_2 =
        [
            multiplier = std::move(mul_ten)
        ] (int val) -> int
        {
            mul_int(multiplier, val);
            return val;
        };
    auto job4b_1 =
        [] (int val) -> int
        {
            print_int(val);
            return val;
        };
    auto job4_join =
        [] (std::tuple<int, int> val) -> int
        {
            return std::get<0>(val) + std::get<1>(val);
        };
    auto job5 =
        [](int val) -> int
        {
            print_int(val);
            return val;
        };

    // build task tree and schedule it
    return schedule_task_tree<int>(
            scheduler,
            std::move(initial_val),
            std::move(job1),
            std::move(job2),
            std::move(job3),/*
            task_tree_openclose(
                std::move(job4_split),
                std::make_tuple(std::move(job4a_1), std::move(job4a_2)),
                std::make_tuple(std::move(job4b_1)),
                std::move(job4_join)
            ),*/
            std::move(job5)
        );

    // problems with a full task graph
    // - when joining, the last joiner should schedule the continuation (can use an atomic int with fetch_add() to
    //   test when all joiners are done)
    // - if an exception cancels a branch, that cancellation needs to immediately propagate to all dependents
    //   - a split should only be canceled if A) at least one parent is canceled, or B) if all children are canceled
    // - want to be able to manually cancel a task? maybe collect cancellation tokens while building a tree...
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(continuation_demo, basic_autorun)
{
    // run the test with a scheduler that immediately invokes tasks
    auto task_tree_future = basic_continuation_demo_test(
            [](auto&& task)
            {
                task();
            }
        );

    // extract final result
    EXPECT_TRUE(task_tree_future.valid());
    const expect<int> final_result{unwrap_future<int>(std::move(task_tree_future))};
    EXPECT_TRUE(final_result);
    EXPECT_NO_THROW(final_result.value());
    std::cerr << "final result: " << final_result.value() << '\n';
}
//-------------------------------------------------------------------------------------------------------------------
TEST(continuation_demo, basic_threadpool)
{
    // run the test with a scheduler that sends tasks into the demo threadpool
    auto task_tree_future = basic_continuation_demo_test(
            [](auto&& task)
            {
                add_task_to_demo_threadpool(std::forward<decltype(task)>(task));
            }
        );

    // run tasks in the threadpool to completion
    int num_tasks_completed{0};
    while (try_run_next_task_demo_threadpool())
    {
        ++num_tasks_completed;
        std::cerr << "completed task #" << num_tasks_completed << '\n';
    }

    // extract final result
    EXPECT_TRUE(task_tree_future.valid());
    const expect<int> final_result{unwrap_future<int>(std::move(task_tree_future))};
    EXPECT_TRUE(final_result);
    EXPECT_NO_THROW(final_result.value());
    std::cerr << "final result: " << final_result.value() << '\n';
}
//-------------------------------------------------------------------------------------------------------------------
