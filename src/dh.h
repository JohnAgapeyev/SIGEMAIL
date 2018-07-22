#ifndef DIFFIE_HELLMAN_H
#define DIFFIE_HELLMAN_H

#include <cstdint>
#include <cstddef>
#include <array>
#include "crypto.h"

class crypto::DH_Keypair {
    secure_array<std::byte, 32> private_key;
    secure_array<std::byte, 32> public_key;
public:
    DH_Keypair();
    DH_Keypair(const DH_Keypair&) = default;
    DH_Keypair(DH_Keypair&&) = default;
    DH_Keypair& operator=(const DH_Keypair&) = default;
    DH_Keypair& operator=(DH_Keypair&&) = default;

    const secure_array<std::byte, 32> generate_shared_secret(const secure_array<std::byte, 32>& remote_public) const noexcept;

    constexpr auto& get_public() const noexcept {return public_key;}
};

#endif
