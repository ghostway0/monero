#include "seraphis_cache.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"

#include "gtest/gtest.h"
#include <boost/range/adaptor/reversed.hpp>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <gtest/gtest.h>
#include <iostream>
#include <map>

uint64_t Cache::get_nearest_block_height_clampdown(const uint64_t test_height)
{
    assert(test_height > m_refresh_height);

    auto checkpoint = m_checkpoints.upper_bound(test_height);
    if (checkpoint == m_checkpoints.end() || checkpoint == m_checkpoints.begin())
        return (uint64_t)(-1);

    return (*--checkpoint).first;
}

void Cache::insert_new_block_ids(const uint64_t first_block_height, const std::vector<crypto::hash> &block_ids)
{
    assert(first_block_height >= m_refresh_height);

    auto erase_begin = m_checkpoints.lower_bound(first_block_height);
    if (erase_begin != m_checkpoints.end())
    {
        m_checkpoints.erase(erase_begin, m_checkpoints.end());
    }

for (size_t i = 0; i < block_ids.size(); i++)
{
        uint64_t current_height = first_block_height + i;
        m_checkpoints[current_height] = block_ids[i];
    }

    if (!m_checkpoints.empty())
        this->clean_prunable_checkpoints();
}

void Cache::clean_prunable_checkpoints()
{
    assert(!m_checkpoints.empty());

    uint64_t latest_height = m_checkpoints.rbegin()->first;
    std::deque<uint64_t> window{};

    auto checkpoint = m_checkpoints.lower_bound(latest_height - m_num_unprunable);
    if (checkpoint == m_checkpoints.end() || checkpoint == m_checkpoints.begin())
        return;
    --checkpoint;

    while (checkpoint != m_checkpoints.begin())
    {
        window.push_back(checkpoint->first);

        if (window.size() >= m_window_size)
        {
            if (should_prune(window, latest_height))
            {
                auto middle = m_checkpoints.lower_bound(window[window.size() / 2]);
                checkpoint = --m_checkpoints.erase(middle);
                window.erase(window.begin() + window.size() / 2);
            } else {
                --checkpoint;
                window.erase(window.begin());
            }
        } else
        {
            --checkpoint;
        }
    }

    checkpoint = m_checkpoints.begin();
    while (checkpoint != m_checkpoints.end() && stored_checkpoints() > m_max_cached_checkpoints)
    {
        // TODO: I don't think max_cached_checkpoints should overrule num_unprunable.
        checkpoint = m_checkpoints.erase(checkpoint);
    }
}

bool Cache::should_prune(const std::deque<uint64_t> &window, const uint64_t chain_top)
{
    assert(window.size() > 0 && chain_top - window.front() > m_num_unprunable);

    uint64_t delta = chain_top - window.front(); // how to incorporate this? sqrt(delta) grows too fast.
    uint64_t width = window.front() - window.back();

    return window.size() * m_max_separation > width; // doesn't seem like max separation anymore.
}

std::vector<crypto::hash> create_dummy_blocks(uint64_t size)
{
    std::vector<crypto::hash> dummy(size, crypto::null_hash);
    return dummy;
}

TEST(seraphis_cache, exceed_max_checkpoints)
{
    uint64_t max_checkpoints = 1;

    Cache cache(max_checkpoints, 0, 0, 0, 3); // max_separation=0, make sure to change this if `should_prune` changes
    auto dummy = create_dummy_blocks(20);
    cache.insert_new_block_ids(0, dummy);

    ASSERT_TRUE(cache.stored_checkpoints() == 1);
}

TEST(seraphis_cache, usage)
{
    // erasing and decrementing, dangerous stuff.
    Cache cache(30, 0, 100, 10, 3);
    auto dummy = create_dummy_blocks(20);
    cache.insert_new_block_ids(0, dummy);
}

TEST(seraphis_cache, greater_refresh)
{
    // refresh height > latest_height - num_unprunable?
}

TEST(seraphis_cache, window_bigger_than_unprunable)
{
    // window > num_unprunable
    Cache cache(30, 0, 1000, 5, 10);
    auto dummy = create_dummy_blocks(20);
    cache.insert_new_block_ids(0, dummy);
    ASSERT_TRUE(cache.stored_checkpoints() == 0);
}
