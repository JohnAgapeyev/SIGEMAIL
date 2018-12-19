#ifndef TEST_H
#define TEST_H

#include <vector>
#include "crypto.h"

crypto::secure_vector<std::byte> get_message();
crypto::secure_vector<std::byte> get_aad();
crypto::shared_key get_key();

#endif /* end of include guard: TEST_H */
