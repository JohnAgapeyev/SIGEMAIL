#ifndef DIFFIE_HELLMAN_H
#define DIFFIE_HELLMAN_H

#include "crypto.h"

class crypto::DH_Keypair {
    crypto::private_key private_key;
    crypto::public_key public_key;

public:
    DH_Keypair();
    DH_Keypair(const DH_Keypair&) = default;
    DH_Keypair(DH_Keypair&&) = default;
    DH_Keypair& operator=(const DH_Keypair&) = default;
    DH_Keypair& operator=(DH_Keypair&&) = default;

    bool operator==(const DH_Keypair& other) const {
        return private_key == other.private_key && public_key == other.public_key;
    }
    bool operator!=(const DH_Keypair& other) const {
        return !(*this == other);
    }

    const crypto::shared_key generate_shared_secret(const crypto::public_key& remote_public) const
            noexcept;

    constexpr auto& get_public() const noexcept { return public_key; }

    friend const crypto::signature crypto::sign_key(
            const DH_Keypair& signing_keypair, const crypto::public_key& key_to_sign);
};

#endif
