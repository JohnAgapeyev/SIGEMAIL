#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <algorithm>
#include "crypto.h"

int main(void) {
    crypto::secure_array<int, 32> good{1, 4, 3, 5, 7, 8, 9, 2};
    std::cout << good[3] << "\n";
    std::fill(good.begin(), good.end(), 3);
    return EXIT_SUCCESS;
}
