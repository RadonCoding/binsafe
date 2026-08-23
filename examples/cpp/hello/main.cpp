#include <iostream>
#include "../../../api/generated/binsafe.hpp"

int main()
{
    BINSAFE_BEGIN();
    std::cout << "Hello, world!" << std::endl;
    return 0;
    BINSAFE_END();
}