#ifndef DIFFIE_HELLMAN_H
#define DIFFIE_HELLMAN_H

#include <cstdint>
#include <cstddef>
#include <array>

struct dh_keypair {
    std::array<std::byte, 32> private_key;
    std::array<std::byte, 32> public_key;
};

dh_keypair *generate_dh_keys(void);
uint8_t *generate_shared_secret(std::array<std::byte, 32> local_private, std::array<std::byte, 32> remote_public);


#endif
