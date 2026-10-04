#include <iostream>
#include <cstdint>
#include "../../../api/binsafe.hpp"

BINSAFE bool validate(char const *serial)
{
    constexpr uint32_t initializer = 0x1505;
    constexpr uint32_t expected = 0x323BFC7A;

    uint32_t hash = initializer;

    for (char const *p = serial; *p; ++p)
    {
        hash = ((hash << 5) + hash) ^ static_cast<uint8_t>(*p);
    }

    return hash == expected;
}

BINSAFE int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: crack-me <serial>" << std::endl;
        return 1;
    }

    if (validate(argv[1]))
    {
        std::cout << "Access granted." << std::endl;
        return 0;
    }

    std::cout << "Access denied." << std::endl;
    return 1;
}
