#include <iostream>
#include <chrono>
#include <cstdint>
#include "../../../api/generated/binsafe.hpp"

int main() {
    uint32_t key[4] = {0xA3B1C2D3, 0xE4F50617, 0x28394A5B, 0x6C7D8E9F};
    uint32_t const delta = 0x9E3779B9;

    uint32_t data_native[2] = {0x12345678, 0x9ABCDEF0};

    auto start_native = std::chrono::high_resolution_clock::now();

    uint32_t v0_nat = data_native[0];
    uint32_t v1_nat = data_native[1];

    for (int i = 0; i < 200000; ++i) {
        uint32_t sum = 0;
        for (uint32_t r = 0; r < 32; r++) {
            v0_nat += (((v1_nat << 4) ^ (v1_nat >> 5)) + v1_nat) ^ (sum + key[sum & 3]);
            sum += delta;
            v1_nat += (((v0_nat << 4) ^ (v0_nat >> 5)) + v0_nat) ^ (sum + key[(sum >> 11) & 3]);
        }
    }

    data_native[0] = v0_nat;
    data_native[1] = v1_nat;

    auto end_native = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> elapsed_native = end_native - start_native;

    uint32_t data_virtualized[2] = {0x12345678, 0x9ABCDEF0};

    auto start_virtualized = std::chrono::high_resolution_clock::now();


    uint32_t v0_virtualized = data_virtualized[0];
    uint32_t v1_virtualized = data_virtualized[1];

    for (int i = 0; i < 200000; ++i) {
        uint32_t sum = 0;
        
        for (uint32_t r = 0; r < 32; r++) {
            v0_virtualized += (((v1_virtualized << 4) ^ (v1_virtualized >> 5)) + v1_virtualized) ^ (sum + key[sum & 3]);
            sum += delta;
            v1_virtualized += (((v0_virtualized << 4) ^ (v0_virtualized >> 5)) + v0_virtualized) ^ (sum + key[(sum >> 11) & 3]);
        }
    }

    data_virtualized[0] = v0_virtualized;
    data_virtualized[1] = v1_virtualized;


    auto end_virtualized = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> elapsed_virtualized = end_virtualized - start_virtualized;

    std::cout << "Native: " << elapsed_native.count() << " ms" << std::endl;
    std::cout << "Virtualized:   " << elapsed_virtualized.count() << " ms" << std::endl;
    std::cout << "Overhead:    " << (elapsed_virtualized.count() / elapsed_native.count()) << "x" << std::endl;

    return 0;
}