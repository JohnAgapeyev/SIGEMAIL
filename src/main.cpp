#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <algorithm>
#include "crypto.h"

int main(void) {
    crypto::secure_array<int, 32> good{1, 4, 3, 5, 7, 8, 9, 2};
    std::cout << good[3] << "\n";
    good.fill(99);
    std::cout << good[3] << "\n";
    return EXIT_SUCCESS;
}
