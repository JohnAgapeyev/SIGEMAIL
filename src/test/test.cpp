#include "logging.h"
#include "server_state.h"
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

session get_session() {
    const auto key = get_key();
    crypto::DH_Keypair kp;
    session s{key, kp.get_public()};
    return s;
}

db::database get_db() {
    return db::database{db::IN_MEMORY_DB};
}

std::array<std::byte, 24> get_truncated_hash(const std::string_view data) {
    const auto hash = crypto::hash_string(data);
    std::array<std::byte, 24> out;
    std::copy(hash.begin(), hash.begin() + 24, out.begin());
    return out;
}

