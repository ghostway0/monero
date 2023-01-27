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

/// Single-writer/multi-reader value containers.
/// - Accessing a moved-from container is UB.
/// - The containers use shared_ptrs internally, so misuse WILL cause reference cycles.

//local headers

//third-party headers
#include <boost/thread/shared_mutex.hpp>

//standard headers
#include <memory>
#include <type_traits>

//forward declarations


namespace tools
{

/// disable const value types
template <typename, typename = void>
struct enable_if_nonconst;
template <typename T>
struct enable_if_nonconst<T, std::enable_if_t<!std::is_const<T>::value>> {};
template <typename T>
struct enable_if_nonconst<T, std::enable_if_t<std::is_const<T>::value>> final { enable_if_nonconst() = delete; };

/// declarations
template <typename>
class read_lock;
template <typename>
class write_lock;
template <typename>
class read_lockable;
template <typename>
class rw_lockable;

/// READ LOCK
template <typename value_t>
class read_lock final : public enable_if_nonconst<value_t>
{
    friend class read_lockable<value_t>;
    friend class rw_lockable<value_t>;

protected:
//constructors
    /// default constructor: disabled
    read_lock() = delete;
    /// normal constructor: only callable by read_lockable and rw_lockable
    read_lock(boost::shared_lock<boost::shared_mutex> lock, std::shared_ptr<value_t> value) :
        m_lock{std::move(lock)},
        m_value{std::move(value)}
    {}
    /// copies: disabled
    read_lock(const read_lock<value_t>&) = delete;
    read_lock& operator=(const read_lock<value_t>&) = delete;

public:
    /// moves: default
    read_lock(read_lock<value_t>&&) = default;
    read_lock& operator=(read_lock<value_t>&&) = default;

//member functions
    /// access the value
    const value_t& value() const { return *m_value; }

private:
//member variables
    boost::shared_lock<boost::shared_mutex> m_lock;
    std::shared_ptr<value_t> m_value;
};

/// WRITE LOCK
template <typename value_t>
class write_lock final  : public enable_if_nonconst<value_t>
{
    friend class rw_lockable<value_t>;

protected:
//constructors
    /// default constructor: disabled
    write_lock() = delete;
    /// normal constructor: only callable by rw_lockable
    write_lock(boost::unique_lock<boost::shared_mutex> lock, std::shared_ptr<value_t> value) :
        m_lock{std::move(lock)},
        m_value{std::move(value)}
    {}
    /// copies: disabled
    write_lock(const write_lock<value_t>&) = delete;
    write_lock& operator=(const write_lock<value_t>&) = delete;

public:
    /// moves: default
    write_lock(write_lock<value_t>&&) = default;
    write_lock& operator=(write_lock<value_t>&&) = default;

//member functions
    /// access the value
    value_t& value() { return *m_value; }

private:
//member variables
    boost::unique_lock<boost::shared_mutex> m_lock;
    std::shared_ptr<value_t> m_value;
};

/// READ LOCKABLE
template <typename value_t>
class read_lockable final  : public enable_if_nonconst<value_t>
{
    friend class rw_lockable<value_t>;

protected:
//constructors
    /// default constructor: disabled
    read_lockable() = delete;
    /// normal constructor: only callable by rw_lockable
    read_lockable(std::shared_ptr<boost::shared_mutex> mutex, std::shared_ptr<value_t> value) :
        m_mutex{std::move(mutex)},
        m_value{std::move(value)}
    {}

public:
    /// normal constructor: from value
    read_lockable(const value_t &raw_value) :
        m_mutex{std::make_shared<boost::shared_mutex>()},
        m_value{std::make_shared<value_t>(raw_value)}
    {}
    read_lockable(value_t &&raw_value) :
        m_mutex{std::make_shared<boost::shared_mutex>()},
        m_value{std::make_shared<value_t>(std::move(raw_value))}
    {}

    /// moves: default and copies: default

//member functions
    /// get a read lock
    /// BLOCKS ON LOCKING THE MUTEX IF THERE IS A CONCURRENT WRITER
    read_lock<value_t> lock() { return read_lock<value_t>{boost::shared_lock<boost::shared_mutex>{*m_mutex}, m_value}; }

private:
//member variables
    std::shared_ptr<boost::shared_mutex> m_mutex;
    std::shared_ptr<value_t> m_value;
};

/// READ/WRITE LOCKABLE
template <typename value_t>
class rw_lockable final  : public enable_if_nonconst<value_t>
{
public:
//constructors
    /// default constructor: disabled
    rw_lockable() = delete;
    /// normal constructor: from value
    rw_lockable(const value_t &raw_value) :
        m_mutex{std::make_shared<boost::shared_mutex>()},
        m_value{std::make_shared<value_t>(raw_value)}
    {}
    rw_lockable(value_t &&raw_value) :
        m_mutex{std::make_shared<boost::shared_mutex>()},
        m_value{std::make_shared<value_t>(std::move(raw_value))}
    {}

    /// copies: disabled
    rw_lockable(const rw_lockable<value_t>&) = delete;
    rw_lockable& operator=(const rw_lockable<value_t>&) = delete;
    /// moves: default
    rw_lockable(rw_lockable<value_t>&&) = default;
    rw_lockable& operator=(rw_lockable<value_t>&&) = default;

//member functions
    /// get a read lockable
    read_lockable<value_t> get_read_lockable() { return read_lockable<value_t>{m_mutex, m_value}; }

    /// get a write lock
    /// BLOCKS ON LOCKING THE MUTEX IF THERE IS A CONCURRENT WRITER OR READERS
    write_lock<value_t> lock() { return write_lock<value_t>{boost::unique_lock<boost::shared_mutex>{*m_mutex}, m_value}; }

private:
//member variables
    std::shared_ptr<boost::shared_mutex> m_mutex;
    std::shared_ptr<value_t> m_value;
};

} //namespace tools
