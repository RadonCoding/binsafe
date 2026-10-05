#include <array>
#include <cstdint>
#include <iostream>
#include "../../../api/binsafe.hpp"

enum class Operation : uint8_t
{
    Add,
    Sub,
    Xor
};

struct Constraint
{
    uint8_t lhs;
    uint8_t rhs;
    Operation operation;
    uint8_t value;
};

template <size_t N>
constexpr auto create(const char (&key)[N])
{
    constexpr size_t length = N - 1;

    std::array<Constraint, (length - 1) * 2> result{};

    size_t out = 0;

    for (size_t i = 0; i < length - 1; ++i)
    {
        const uint8_t a = static_cast<uint8_t>(key[i]);
        const uint8_t b = static_cast<uint8_t>(key[i + 1]);

        result[out++] = {
            static_cast<uint8_t>(i),
            static_cast<uint8_t>(i + 1),
            Operation::Add,
            static_cast<uint8_t>(a + b)};

        result[out++] = {
            static_cast<uint8_t>(i),
            static_cast<uint8_t>(i + 1),
            Operation::Xor,
            static_cast<uint8_t>(a ^ b)};
    }

    return result;
}

template <size_t i, auto &constraints>
BINSAFE bool validate(char const *serial)
{
    if constexpr (i == constraints.size())
    {
        return true;
    }
    else
    {
        const Constraint &constraint = constraints[i];

        const uint8_t lhs =
            static_cast<uint8_t>(serial[constraint.lhs]);

        const uint8_t rhs =
            static_cast<uint8_t>(serial[constraint.rhs]);

        bool valid = false;

        switch (constraint.operation)
        {
        case Operation::Add:
            valid = static_cast<uint8_t>(lhs + rhs) == constraint.value;
            break;

        case Operation::Sub:
            valid = static_cast<uint8_t>(lhs - rhs) == constraint.value;
            break;

        case Operation::Xor:
            valid = static_cast<uint8_t>(lhs ^ rhs) == constraint.value;
            break;
        }

        return valid && validate<i + 1, constraints>(serial);
    }
}

constexpr auto constraints =
    create("0xP4553D17501P455");

BINSAFE bool validate(char const *serial)
{
    constexpr size_t length = (constraints.size() / 2) + 1;

    for (size_t i = 0; i < length; ++i)
    {
        if (serial[i] == '\0')
            return false;
    }

    if (serial[length] != '\0')
        return false;

    return validate<0, constraints>(serial);
}

BINSAFE int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: crack-me <serial>\n";
        return 1;
    }

    if (validate(argv[1]))
    {
        std::cout << "Access granted.\n";
        return 0;
    }

    std::cout << "Access denied.\n";
    return 0;
}