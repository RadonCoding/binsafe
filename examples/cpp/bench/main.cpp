#include <iostream>
#include <chrono>
#include <cstdint>
#include <cassert>
#include "../../../api/binsafe.hpp"

#define ENCIPHER(data, key, delta)                                                     \
    do                                                                                 \
    {                                                                                  \
        uint32_t v0 = (data)[0];                                                       \
        uint32_t v1 = (data)[1];                                                       \
                                                                                       \
        for (int i = 0; i < 10000; ++i)                                                \
        {                                                                              \
            uint32_t sum = 0;                                                          \
                                                                                       \
            for (uint32_t r = 0; r < 32; r++)                                          \
            {                                                                          \
                v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + (key)[sum & 3]);         \
                sum += (delta);                                                        \
                v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + (key)[(sum >> 11) & 3]); \
            }                                                                          \
        }                                                                              \
                                                                                       \
        (data)[0] = v0;                                                                \
        (data)[1] = v1;                                                                \
    } while (0)

BINSAFE void encipher(uint32_t data[2], uint32_t const key[4], uint32_t delta)
{
    ENCIPHER(data, key, delta);
}

int main()
{
    constexpr uint32_t key[4] = {0xA3B1C2D3, 0xE4F50617, 0x28394A5B, 0x6C7D8E9F};
    constexpr uint32_t delta = 0x9E3779B9;

    uint32_t data_native[2] = {0x12345678, 0x9ABCDEF0};

    std::chrono::high_resolution_clock::time_point start_native = std::chrono::high_resolution_clock::now();

    ENCIPHER(data_native, key, delta);

    std::chrono::high_resolution_clock::time_point end_native = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> elapsed_native = end_native - start_native;

    uint32_t data_virtualized[2] = {0x12345678, 0x9ABCDEF0};

    std::chrono::high_resolution_clock::time_point start_virtualized = std::chrono::high_resolution_clock::now();

    encipher(data_virtualized, key, delta);

    std::chrono::high_resolution_clock::time_point end_virtualized = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> elapsed_virtualized = end_virtualized - start_virtualized;

    assert(data_native[0] == data_virtualized[0]);
    assert(data_native[1] == data_virtualized[1]);

    std::cout << "Native: " << elapsed_native.count() << " ms" << std::endl;
    std::cout << "Virtualized: " << elapsed_virtualized.count() << " ms" << std::endl;
    std::cout << "Overhead: " << (elapsed_virtualized.count() / elapsed_native.count()) << "x" << std::endl;

    return 0;
}
