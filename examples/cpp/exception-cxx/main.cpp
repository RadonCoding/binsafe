#include <iostream>
#include <cstdint>
#include <cassert>
#include "../../../api/binsafe.hpp"

BINSAFE uint32_t guarded(uint32_t value)
{
    try
    {
        throw value;
    }
    catch (uint32_t caught)
    {
        return caught;
    }

    return 0;
}

int main()
{
    constexpr uint32_t value = 0x12345678;

    uint32_t a = 0;
    uint32_t b = 0;

    try
    {
        throw value;
    }
    catch (uint32_t caught)
    {
        a = caught;
    }

    b = guarded(value);

    assert(a == b);

    return 0;
}
