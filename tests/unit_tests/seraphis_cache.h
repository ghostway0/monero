#pragma once

#include "crypto/hash.h"
#include <cstdint>
#include <deque>
#include <map>

// just a placeholder
class PruningStrategy
{
  public:
    virtual bool should_prune(const std::deque<uint64_t> &window, uint64_t chain_top) = 0;
};

class HalfPruning : public PruningStrategy
{
  public:
    HalfPruning(uint64_t num_unprunable, uint64_t max_separation)
        : m_num_unprunable(num_unprunable), m_max_separation(max_separation)
    {
    }

    bool should_prune(const std::deque<uint64_t> &window, uint64_t chain_top);

  private:
    uint64_t m_num_unprunable;
    uint64_t m_max_separation;
};

class Cache
{
  public:
    Cache(uint64_t max_cached_checkpoints,
        uint64_t refresh_height,
        uint64_t window_size,
        uint64_t max_separation,
        PruningStrategy &strategy)
        : m_max_cached_checkpoints(max_cached_checkpoints), m_refresh_height(refresh_height),
          m_window_size(window_size), m_max_separation(max_separation), m_strategy(strategy), m_checkpoints{}
    {
        assert(window_size % 2 == 0 && window_size > 2);
    }

    uint64_t get_nearest_block_height_clampdown(uint64_t test_height);
    void insert_new_block_ids(uint64_t first_block_height, std::vector<crypto::hash> block_ids);

  private:
    uint64_t m_max_cached_checkpoints;
    uint64_t m_refresh_height;
    uint64_t m_window_size;
    PruningStrategy &m_strategy;
    std::map<uint64_t, crypto::hash> m_checkpoints;
    uint64_t m_max_separation;

    void clean_prunable_checkpoints();
};
