#ifndef TEST_H
#define TEST_H

#include <vector>
#include "crypto.h"
#include "session.h"

crypto::secure_vector<std::byte> get_message();
crypto::secure_vector<std::byte> get_aad();
crypto::shared_key get_key();

session get_session();

#endif /* end of include guard: TEST_H */
