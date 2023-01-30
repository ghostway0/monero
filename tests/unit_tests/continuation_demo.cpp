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

#include <gtest/gtest.h>

#include <iostream>
#include <memory>
#include <queue>

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
class Task
{
//member types
    class TaskConcept
    {
    public:
        TaskConcept&& operator=(TaskConcept&&) = delete;  //disable copies/moves (this is a virtual base class)
        virtual ~TaskConcept() = default;
        virtual void run() = 0;
    };

    //todo: test if T is invokable?
    template <typename T>
    class TaskModel final : public TaskConcept
    {
    public:
    //constructors
        /// default constructor: disabled
        TaskModel() = delete;
        /// normal constructor
        TaskModel(T task) : m_task{std::move(task)}
        {}
        /// disable copies/moves
        TaskModel&& operator=(TaskModel&&) = delete;
    //member functions
        /// run the task
        void run() override
        {
            m_task();
        }
    private:
    //member variables
        /// the task
        T m_task;
    };

public:
//constructors
    /// default constructor: disabled
    Task() = delete;
    /// construct from actual task
    template <typename T>
    Task(T task) : m_task{std::make_unique<TaskModel<T>>(std::move(task))}
    {}

//member functions
    void run()
    {
        m_task->run();
    }

private:
//member variables
    std::unique_ptr<TaskConcept> m_task;
};
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
class ThreadPool
{
public:
    void add_task(Task new_task)
    {
        m_pending_tasks.push(std::move(new_task));
    }

    bool try_run_next_task()
    {
        // check if there are any tasks
        if (m_pending_tasks.size() == 0)
            return false;

        // run the oldest task
        Task task_to_run{std::move(m_pending_tasks.front())};
        m_pending_tasks.pop();
        task_to_run.run();

        return true;
    }

private:
    std::queue<Task> m_pending_tasks;
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
static void add_task_to_demo_threadpool(Task new_task)
{
    detail::get_demo_threadpool().add_task(std::move(new_task));
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
// unary case
//-------------------------------------------------------------------------------------------------------------------
template <typename A>
static auto build_task_chain(A a)
{
    return std::move(a);
}
//-------------------------------------------------------------------------------------------------------------------
// fold into task 'a' its continuation 'the rest of the task chain'
//-------------------------------------------------------------------------------------------------------------------
template <typename A, typename... Types>
static auto build_task_chain(A a, Types... args)
{
    return
        [
            this_task = std::move(a),
            next_task = build_task_chain(std::move(args)...)
        ] (auto val)
        {
            // this task's job
            auto this_task_result = this_task(std::move(val));

            // connect the next task to this task
            auto continuation =
                [
                    val  = std::move(this_task_result),
                    task = std::move(next_task)
                ] ()
                {
                    task(std::move(val));
                };

            // submit the continuation task to the threadpool
            add_task_to_demo_threadpool(std::move(continuation));
        };
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
template <typename I, typename T>
static auto initialize_task(I initial_value, T task)
{
    return
        [
            initial_value = std::move(initial_value),
            task = std::move(task)
        ] ()
        {
            task(std::move(initial_value));
        };
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
TEST(continuation_demo, basic_ergonomic)
{
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

    // build and submit the task chain
    add_task_to_demo_threadpool(
            initialize_task(
                    std::move(val),
                    build_task_chain(
                            std::move(job1),
                            std::move(job2),
                            std::move(job3)
                        )
                )
        );

    // run tasks to completion
    int num_tasks_completed{0};
    while (try_run_next_task_demo_threadpool())
    {
        ++num_tasks_completed;
        std::cerr << "completed task #" << num_tasks_completed << '\n';
    }
}
//-------------------------------------------------------------------------------------------------------------------
