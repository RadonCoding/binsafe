#include <iostream>
#include <cstdint>
#include <cassert>
#include <thread>
#include <vector>
#include "../../../api/binsafe.hpp"

BINSAFE uint32_t echo(uint32_t input)
{
    uint32_t output = input;

    return output;
}

int main()
{
    constexpr int thread_count = 8;

    constexpr uint32_t value = 0x12345678;

    uint32_t results[thread_count] = {};

    std::thread threads[thread_count];

    for (int i = 0; i < thread_count; ++i)
    {
        threads[i] = std::thread([&, i]()
                                 { results[i] = echo(value); });
    }

    for (int i = 0; i < thread_count; ++i)
    {
        threads[i].join();
    }

    for (int i = 0; i < thread_count; ++i)
    {
        assert(results[i] == value);
    }

    return 0;
}
