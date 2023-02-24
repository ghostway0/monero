#include "seraphis_cache.h"

#include <boost/range/adaptor/reversed.hpp>
#include <gtest/gtest.h>

bool HalfPruning::should_prune(const std::deque<uint64_t> &window, uint64_t chain_top)
{
    if (chain_top - *window.end() <= m_num_unprunable)
        return false;

    uint64_t width = *window.end() - *window.begin();
    return window.size() * m_max_separation > width;
}

uint64_t Cache::get_nearest_block_height_clampdown(uint64_t test_height)
{
    if (test_height < m_refresh_height)
        return (uint64_t)(-1);

    auto checkpoint = m_checkpoints.upper_bound(test_height);
    if (checkpoint == m_checkpoints.end())
        return (uint64_t)(-1);

    return (*--checkpoint).first;
}

void Cache::insert_new_block_ids(uint64_t first_block_height, std::vector<crypto::hash> block_ids)
{
    auto erase_begin = m_checkpoints.lower_bound(first_block_height);
    if (erase_begin != m_checkpoints.end())
    {
        m_checkpoints.erase(erase_begin, m_checkpoints.end());
    }

    for (size_t i = 0; i < block_ids.size(); i++)
    {
        uint64_t current_height = first_block_height + i;
        m_checkpoints.insert({current_height, block_ids[i]});
    }

    clean_prunable_checkpoints();
}

void Cache::clean_prunable_checkpoints()
{
    uint64_t latest_height = m_checkpoints.end()->first;
    std::deque<uint64_t> window{};
    window.resize(m_window_size / 2 - 2, m_refresh_height - m_max_separation);

    for (const auto &checkpoint : boost::adaptors::reverse(m_checkpoints))
    {
        window.push_back(checkpoint.first);

        if (window.size() >= m_window_size)
        {
            if (m_strategy.should_prune(window, latest_height))
            {
                uint64_t middle = window.at(window.size() / 2);
                m_checkpoints.erase(middle);
            }

            m_checkpoints.erase(*window.begin());
        }
    }
}

TEST(seraphis_cache, main)
{
    HalfPruning h(10, 100000);
    Cache cache(100, 0, 10, h);

    cache.insert_new_block_ids(10, {});
    // something something
}
