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
#include <stdexcept>

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
template <typename T>
bool future_is_ready(const std::future<T> &future)
{
    if (!future.valid())
        return false;
    if (future.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
        return false;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename T>
bool future_is_ready(const std::shared_future<T> &future)
{
    if (!future.valid())
        return false;
    if (future.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
        return false;
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename R>
expect<R> unwrap_future(std::future<R> &future)
{
    if (!future_is_ready(future)) { return std::error_code{};       }
    try                           { return std::move(future.get()); }
    catch (std::error_code e)     { return e;                       }
    catch (...)                   { return std::error_code{};       }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename T>
struct Task final
{
    unsigned char id;
    T task;
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename T>
Task<T> make_task(const unsigned char id, T &&task)
{
    return Task<T>{.id = id, .task = std::forward<T>(task)};
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
/// declare the monitor builder
template <typename>
class TaskGraphMonitorBuilder;

/// monitor a task graph
/// - destroying the monitor will immediately cancel the graph (i.e. it assumes the graph has no desired side effects
///   other than setting the future result)
template <typename R>
class TaskGraphMonitor final
{
    friend class TaskGraphMonitorBuilder<R>;

public:
    bool is_canceled() const { return future_is_ready(m_cancellation_flag); }
    bool has_result()  const { return future_is_ready(m_final_result);      }

    void cancel()
    {
        if (!this->is_canceled() && m_cancellation_handle)
        {
            try { m_cancellation_handle->set_value(); } catch (...) { /* already canceled */ }
        }
    }
    expect<R> expect_result() { return unwrap_future(m_final_result); }

protected:
    std::shared_ptr<std::promise<void>> m_cancellation_handle;
    std::shared_future<void> m_cancellation_flag;
    std::future<R> m_final_result;
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename R>
class TaskGraphMonitorBuilder final
{
public:
    /// construct from the future result
    TaskGraphMonitorBuilder(std::future<R> future_result)
    {
        m_monitor.m_cancellation_handle = std::make_shared<std::promise<void>>();
        m_monitor.m_cancellation_flag   = m_monitor.m_cancellation_handle->get_future().share();
        m_monitor.m_final_result        = std::move(future_result);
    }

    /// add a task
    std::shared_future<void> add_task(const unsigned char task_id,
        std::future<void> task_completion_flag,
        std::weak_ptr<std::promise<void>> &weak_cancellation_handle_out)
    {
        weak_cancellation_handle_out = m_monitor.m_cancellation_handle;
        return m_monitor.m_cancellation_flag;
    }

    /// cancel the task graph (useful if a failure is encountered while building the graph)
    void cancel() { m_monitor.cancel(); }

    /// extract the monitor
    TaskGraphMonitor<R> get_monitor()
    {
        if(!m_monitor.m_cancellation_flag.valid())
            throw std::runtime_error{"task graph monitor builder: already extracted monitor."};

        return std::move(m_monitor);
    }

private:
    TaskGraphMonitor<R> m_monitor;
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void force_set_cancellation_flag(std::weak_ptr<std::promise<void>> &weak_cancellation_handle)
{
    try         { if (auto cancellation_handle{weak_cancellation_handle.lock()}) cancellation_handle->set_value(); }
    catch (...) { /* failure to set the flag means it's already set */ }
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
template <typename R, typename S, typename T>
static auto build_task_graph(TaskGraphMonitorBuilder<R> &graph_monitor_builder_inout, S, Task<T> &&this_task)
{
    std::promise<void> completion_handle{};
    std::weak_ptr<std::promise<void>> cancellation_handle;
    std::shared_future<void> cancellation_flag{
            graph_monitor_builder_inout.add_task(this_task.id, completion_handle.get_future(), cancellation_handle)
        };

    return
        [
            l_task                = std::forward<Task<T>>(this_task).task,
            l_completion_handle   = std::move(completion_handle),
            l_cancellation_handle = std::move(cancellation_handle),
            l_cancellation_flag   = std::move(cancellation_flag)
        ] (auto&& this_task_val, std::promise<R> promise) mutable -> void
        {
            // check for cancellation
            if (future_is_ready(l_cancellation_flag))
                return;

            // execute the task
            try
            {
                promise.set_value(l_task(std::move(this_task_val)));
                l_completion_handle.set_value();
            }
            catch (...)
            {
                try
                {
                    promise.set_exception(std::current_exception());
                    l_completion_handle.set_exception(std::current_exception());
                } catch (...) { /*can't do anything*/ }
                force_set_cancellation_flag(l_cancellation_handle);  //set cancellation flag for consistency
            }
        };
}
//-------------------------------------------------------------------------------------------------------------------
// fold into task 'a' its continuation 'the rest of the task graph'
//-------------------------------------------------------------------------------------------------------------------
template <typename R, typename S, typename T, typename... Ts>
static auto build_task_graph(TaskGraphMonitorBuilder<R> &graph_monitor_builder_inout,
    S scheduler,
    Task<T> &&this_task,
    Task<Ts> &&...continuation_tasks)
{
    std::promise<void> completion_handle{};
    std::weak_ptr<std::promise<void>> cancellation_handle;
    std::shared_future<void> cancellation_flag{
            graph_monitor_builder_inout.add_task(this_task.id, completion_handle.get_future(), cancellation_handle)
        };

    return
        [
            l_scheduler           = scheduler,
            l_this_task           = std::forward<Task<T>>(this_task).task,
            l_completion_handle   = std::move(completion_handle),
            l_next_task           = build_task_graph<R>(
                                        graph_monitor_builder_inout,
                                        scheduler,
                                        std::forward<Task<Ts>>(continuation_tasks)...
                                    ),
            l_cancellation_handle = std::move(cancellation_handle),
            l_cancellation_flag   = std::move(cancellation_flag)
        ] (auto&& this_task_val, std::promise<R> promise) mutable -> void
        {
            try
            {
                // check for cancellation
                if (future_is_ready(l_cancellation_flag))
                    return;

                // this task's job
                auto this_task_result =
                    [&]() -> expect<decltype(l_this_task(std::declval<decltype(this_task_val)>()))>
                    {
                        try { return l_this_task(std::forward<decltype(this_task_val)>(this_task_val)); }
                        catch (...)
                        {
                            try
                            {
                                promise.set_exception(std::current_exception());
                                l_completion_handle.set_exception(std::current_exception());
                            } catch (...) { /*can't do anything*/ }
                            return std::error_code{};
                        }
                    }();

                // give up if this task failed
                // - force-set the cancellation flag so all dependents in other branches of the graph will be cancelled
                if (!this_task_result)
                {
                    force_set_cancellation_flag(l_cancellation_handle);
                    return;
                }

                // check for cancellation again (can discard the task result if cancelled)
                if (future_is_ready(l_cancellation_flag))
                    return;

                // pass the result of this task to the continuation
                auto continuation = initialize_future_task(
                        std::forward<typename decltype(this_task_result)::value_type>(
                                std::move(this_task_result).value()
                            ),
                        std::move(l_next_task),
                        std::move(promise)
                    );

                // mark success
                // - do this before scheduling the next task in case the scheduler immediately invokes the continuation
                try { l_completion_handle.set_value(); } catch (...) { /* don't kill the next task */ }

                // submit the continuation task to the scheduler
                l_scheduler(std::move(continuation));
            } catch (...) { force_set_cancellation_flag(l_cancellation_handle); }
        };
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename R, typename S, typename I, typename... Ts>
static TaskGraphMonitor<R> schedule_task_graph(S scheduler, I &&initial_value, Task<Ts> &&...tasks)
{
    // prepare result channel
    std::promise<R> result_promise;
    std::future<R> result_future{result_promise.get_future()};

    // build task graph
    TaskGraphMonitorBuilder<R> monitor_builder{std::move(result_future)};

    try
    {
        auto task_graph_head = initialize_future_task(
                std::forward<I>(initial_value),
                build_task_graph<R>(monitor_builder, scheduler, std::forward<Task<Ts>>(tasks)...),
                std::move(result_promise)
            );

        // schedule task graph
        scheduler(std::move(task_graph_head));
    }
    catch (...)
    {
        // assume if launching the task graph failed then it should be canceled
        monitor_builder.cancel();
    }

    // return future
    return monitor_builder.get_monitor();
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename S>
static auto basic_continuation_demo_test(S scheduler)
{
    // set up the basic task sequence in reverse order
    int initial_val{10};
    int add_five{5};
    int mul_three{3}; (void)mul_three;
    int mul_ten{10}; (void)mul_ten; (void)mul_int;
    // task 1: print
    // task 2: add 5
    // task 3: print
    // task 4 SPLIT: divide in half for each branch
    //   task 4a-1: print    task 4b-1: print
    //   task 4a-2: mul10
    // task 4 JOIN: add together each branch
    // task 5 print
    auto job1 = make_task(1,
            [](int val) -> int
            {
                print_int(val);
                return val;
            }
        );
    auto job2 = make_task(2,
            [
                addor = std::move(add_five)
            ] (int val) -> int
            {
                add_int(addor, val);
                return val;
            }
        );
    auto job3 = make_task(3,
            [](int val) -> int
            {
                print_int(val);
                return val;
            }
        );/*
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
        };*/

    // build task graph and schedule it
    return schedule_task_graph<int>(
            scheduler,
            std::move(initial_val),
            std::move(job1),
            std::move(job2),
            std::move(job3)/*,
            task_graph_openclose(
                std::move(job4_split),
                std::make_tuple(std::move(job4a_1), std::move(job4a_2)),
                std::make_tuple(std::move(job4b_1)),
                std::move(job4_join)
            ),
            std::move(job5)*/
        );

    // problems with a full task graph
    // - when joining, the last joiner should schedule the continuation (can use an atomic int with fetch_add() to
    //   test when all joiners are done)

    // todo
    // - is_canceled() callback for tasks that can cancel themselves
    // - make detached task graph by moving the task graph monitor into the last task's lambda capture
    //   - detached graphs should have void return type (last task returns nothing)
    //   - detached graphs can be built sideways within a large graph construction, using a fresh monitor builder
    //   - detached graphs are not cancellable; if a cancellable process is desired, don't use a detached graph, just
    //     use a normal graph and keep track of the graph monitor (which will auto-cancel the graph when destroyed)
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(continuation_demo, basic_autorun)
{
    // run the test with a scheduler that immediately invokes tasks
    TaskGraphMonitor<int> task_graph_monitor = basic_continuation_demo_test(
            [](auto&& task)
            {
                task();
            }
        );

    // extract final result
    EXPECT_TRUE(task_graph_monitor.has_result());
    const expect<int> final_result{task_graph_monitor.expect_result()};
    EXPECT_TRUE(final_result);
    EXPECT_NO_THROW(final_result.value());
    std::cerr << "final result: " << final_result.value() << '\n';
}
//-------------------------------------------------------------------------------------------------------------------
TEST(continuation_demo, basic_threadpool)
{
    // run the test with a scheduler that sends tasks into the demo threadpool
    TaskGraphMonitor<int> task_graph_monitor = basic_continuation_demo_test(
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
    EXPECT_TRUE(task_graph_monitor.has_result());
    const expect<int> final_result{task_graph_monitor.expect_result()};
    EXPECT_TRUE(final_result);
    EXPECT_NO_THROW(final_result.value());
    std::cerr << "final result: " << final_result.value() << '\n';
}
//-------------------------------------------------------------------------------------------------------------------
