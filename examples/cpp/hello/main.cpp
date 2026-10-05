#include <iostream>
#include "../../../api/binsafe.hpp"

BINSAFE void hello()
{
    std::cout << "Hello, world!" << std::endl;
}

int main()
{
    hello();
    return 0;
}
