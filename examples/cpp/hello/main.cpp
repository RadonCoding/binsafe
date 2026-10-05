#include <iostream>
#include "../../../api/binsafe.hpp"

extern "C" BINSAFE void hello()
{
    std::cout << "Hello, world!" << std::endl;
}

int main()
{
    hello();
    return 0;
}
