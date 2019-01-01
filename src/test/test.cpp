#include "test.h"

crypto::secure_vector<std::byte> get_message() {
    crypto::secure_vector<std::byte> out;
    out.assign(76, std::byte{'a'});
    return out;
}

crypto::secure_vector<std::byte> get_aad() {
    crypto::secure_vector<std::byte> out;
    out.assign(3, std::byte{'b'});
    return out;
}

crypto::shared_key get_key() {
    crypto::shared_key out;
    out.fill(std::byte{'c'});
    return out;
}

