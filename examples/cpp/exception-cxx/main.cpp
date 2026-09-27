#include <iostream>
#include <cstdint>
#include <cassert>
#include "../../../api/generated/binsafe.hpp"

int main() {
    uint32_t a = 0;
    uint32_t b = 0;

    try {
        throw 0x12345678;
    }
    catch (int value) {
        a = static_cast<uint32_t>(value);
    }

    BINSAFE_BEGIN();

    try {        
        throw 0x12345678;
    }
    catch (int value) {
        std::cout << "caught" << std::endl;

        b = static_cast<uint32_t>(value);
    }

    BINSAFE_END();

    assert(a == b);

    std::cout << "OK" << std::endl;

    return 0;
}