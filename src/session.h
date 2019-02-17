#ifndef PROTOCOL_STATE_H
#define PROTOCOL_STATE_H

#include <boost/serialization/access.hpp>
#include <boost/serialization/array.hpp>
#include <boost/serialization/optional.hpp>
#include <boost/serialization/unordered_map.hpp>
#include <boost/serialization/variant.hpp>
#include <boost/serialization/vector.hpp>
#include <cstdint>
#include <optional>

#include "crypto.h"
#include "dh.h"
#include "key_pack.h"
#include "logging.h"
#include "message.h"

extern const uint64_t MAX_SKIP;

class session {
public:
    //Sender initialization
    session(crypto::shared_key shared_secret, crypto::DH_Keypair self_ephem,
            crypto::public_key dest_public_key, crypto::public_key initial_id_public,
            std::optional<crypto::public_key> initial_otpk_public);
    //Receiver initialization
    session(crypto::shared_key shared_secret, crypto::DH_Keypair self_kp, crypto::public_key);
    ~session() = default;
    session(const session&) = default;
    session(session&&) = default;
    session& operator=(session&&) = default;
    session& operator=(const session&) = default;

    bool operator==(const session& other) const;
    bool operator!=(const session& other) const { return !(*this == other); }

    const signal_message ratchet_encrypt(const crypto::secure_vector<std::byte>& plaintext,
            const crypto::secure_vector<std::byte>& aad);

    const crypto::secure_vector<std::byte> ratchet_decrypt(const signal_message& message);

private:
    void skip_message_keys(uint64_t until);

    const std::optional<crypto::secure_vector<std::byte>> try_skipped_message_keys(
            const signal_message& message);

    void DH_ratchet(const crypto::public_key& remote_pub_key);

    crypto::DH_Keypair self_keypair;
    crypto::public_key remote_public_key;
    crypto::shared_key root_key;
    crypto::shared_key send_chain_key;
    crypto::shared_key receive_chain_key;
    uint64_t send_message_num = 0;
    uint64_t receive_message_num = 0;
    uint64_t previous_send_chain_size = 0;

    std::optional<initial_message_header> initial_header_contents;
    std::optional<crypto::shared_key> initial_secret_key;

    crypto::secure_unordered_map<std::pair<crypto::public_key, uint64_t>, crypto::shared_key>
            skipped_keys;

    friend class boost::serialization::access;
    template<class Archive>
    void save(Archive& ar, const unsigned int version) const {
        boost::ignore_unused_variable_warning(version);
        ar& self_keypair;
        ar& remote_public_key;
        ar& root_key;
        ar& send_chain_key;
        ar& receive_chain_key;
        ar& send_message_num;
        ar& receive_message_num;
        ar& previous_send_chain_size;

        std::unordered_map<std::pair<crypto::public_key, uint64_t>, crypto::shared_key,
                boost::hash<std::pair<crypto::public_key, uint64_t>>>
                tmp;

        for (auto [key, value] : skipped_keys) {
            tmp.emplace(std::move(key), std::move(value));
        }

        ar& tmp;

        if (initial_header_contents == std::nullopt) {
            boost::optional<initial_message_header> boost_tmp{boost::none};
            ar& boost_tmp;
        } else {
            boost::optional<initial_message_header> boost_tmp = *initial_header_contents;
            ar& boost_tmp;
        }
        if (initial_secret_key == std::nullopt) {
            boost::optional<crypto::shared_key> boost_tmp{boost::none};
            ar& boost_tmp;
        } else {
            boost::optional<crypto::shared_key> boost_tmp = *initial_secret_key;
            ar& boost_tmp;
        }
    }
    template<class Archive>
    void load(Archive& ar, const unsigned int version) {
        boost::ignore_unused_variable_warning(version);
        ar& self_keypair;
        ar& remote_public_key;
        ar& root_key;
        ar& send_chain_key;
        ar& receive_chain_key;
        ar& send_message_num;
        ar& receive_message_num;
        ar& previous_send_chain_size;

        std::unordered_map<std::pair<crypto::public_key, uint64_t>, crypto::shared_key,
                boost::hash<std::pair<crypto::public_key, uint64_t>>>
                tmp;
        ar& tmp;

        for (auto [key, value] : tmp) {
            skipped_keys.emplace(std::move(key), std::move(value));
        }

        boost::optional<initial_message_header> tmp_head;
        ar& tmp_head;

        if (tmp_head.has_value()) {
            initial_header_contents = *tmp_head;
        } else {
            initial_header_contents = std::nullopt;
        }

        boost::optional<crypto::shared_key> tmp_key;
        ar& tmp_key;

        if (tmp_key.has_value()) {
            initial_secret_key = *tmp_key;
        } else {
            initial_secret_key = std::nullopt;
        }
    }
    BOOST_SERIALIZATION_SPLIT_MEMBER()
};

std::pair<session, crypto::secure_vector<std::byte>> decrypt_initial_message(
        const signal_message& message, const crypto::DH_Keypair& identity,
        const crypto::DH_Keypair& prekey, const crypto::DH_Keypair& one_time);
std::pair<session, crypto::secure_vector<std::byte>> decrypt_initial_message(
        const signal_message& message, const crypto::DH_Keypair& identity,
        const crypto::DH_Keypair& prekey);

#endif /* end of include guard: PROTOCOL_STATE_H */
