#include <iostream>
#include <cstdint>
#include <cassert>
#include "../../../api/binsafe.hpp"

BINSAFE uint32_t guarded(int value)
{
    try {
        throw value;
    }
    catch (int caught) {
        return static_cast<uint32_t>(caught);
    }

    return 0;
}

int main() {
    constexpr int value = 0x12345678;

    uint32_t a = 0;
    uint32_t b = 0;

    try {
        throw value;
    }
    catch (int value) {
        a = static_cast<uint32_t>(value);
    }

    b = guarded(value);

    assert(a == b);

    return 0;
}
