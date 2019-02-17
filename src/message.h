#ifndef MESSAGE_H
#define MESSAGE_H

#include <array>
#include <boost/optional/optional.hpp>
#include <boost/serialization/access.hpp>
#include <boost/serialization/array.hpp>
#include <boost/serialization/optional.hpp>
#include <boost/serialization/variant.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/variant/get.hpp>
#include <boost/variant/variant.hpp>
#include <cstdint>
#include <openssl/crypto.h>
#include <optional>

#include "crypto.h"

struct message_header {
    crypto::public_key dh_public_key;
    uint64_t prev_chain_len;
    uint64_t message_num;

    bool operator==(const message_header& other) const {
        return dh_public_key == other.dh_public_key && prev_chain_len == other.prev_chain_len
                && message_num == other.message_num;
    }
    bool operator!=(const message_header& other) const { return !(*this == other); }

    friend class boost::serialization::access;
    template<class Archive>
    void serialize(Archive& ar, const unsigned int version) {
        boost::ignore_unused_variable_warning(version);
        ar& dh_public_key;
        ar& prev_chain_len;
        ar& message_num;
    }
};

struct initial_message_header {
    crypto::public_key identity_key;
    crypto::public_key ephemeral_key;
    //This is the public key of the one-time key that was used in the initial message
    std::optional<crypto::public_key> remote_one_time_public_key;

    bool operator==(const initial_message_header& other) const {
        return identity_key == other.identity_key && ephemeral_key == other.ephemeral_key
                && remote_one_time_public_key == other.remote_one_time_public_key;
    }
    bool operator!=(const initial_message_header& other) const { return !(*this == other); }

    friend class boost::serialization::access;
    template<class Archive>
    void save(Archive& ar, const unsigned int version) const {
        boost::ignore_unused_variable_warning(version);
        ar& identity_key;
        ar& ephemeral_key;

        if (remote_one_time_public_key == std::nullopt) {
            boost::optional<crypto::public_key> one_time_opt{boost::none};
            ar& one_time_opt;
        } else {
            boost::optional<crypto::public_key> one_time_opt = *remote_one_time_public_key;
            ar& one_time_opt;
        }
    }
    template<class Archive>
    void load(Archive& ar, const unsigned int version) {
        boost::ignore_unused_variable_warning(version);
        ar& identity_key;
        ar& ephemeral_key;

        boost::optional<crypto::public_key> one_time_opt;
        ar& one_time_opt;

        if (one_time_opt.has_value()) {
            remote_one_time_public_key = *one_time_opt;
        } else {
            remote_one_time_public_key = std::nullopt;
        }
    }
    BOOST_SERIALIZATION_SPLIT_MEMBER()
};

struct signal_message {
    std::variant<message_header, initial_message_header> header;
    crypto::secure_vector<std::byte> message;
    crypto::secure_vector<std::byte> aad;

    bool operator==(const signal_message& other) const {
        return header == other.header && message == other.message && aad == other.aad;
    }
    bool operator!=(const signal_message& other) const { return !(*this == other); }

    friend class boost::serialization::access;
    template<class Archive>
    void save(Archive& ar, const unsigned int version) const {
        boost::ignore_unused_variable_warning(version);

        if (std::holds_alternative<initial_message_header>(header)) {
            //Initial message header
            boost::variant<message_header, initial_message_header> bh{
                    std::get<initial_message_header>(header)};
            ar& bh;
        } else {
            //Regular message header
            boost::variant<message_header, initial_message_header> bh{
                    std::get<message_header>(header)};
            ar& bh;
        }

        ar& message;
        ar& aad;
    }

    template<class Archive>
    void load(Archive& ar, const unsigned int version) {
        boost::ignore_unused_variable_warning(version);

        boost::variant<message_header, initial_message_header> bh;

        ar& bh;

        if (bh.which() == 1) {
            //Initial message header
            header = boost::get<initial_message_header>(bh);
        } else {
            //Regular message header
            header = boost::get<message_header>(bh);
        }

        ar& message;
        ar& aad;
    }
    BOOST_SERIALIZATION_SPLIT_MEMBER()
};

std::string serialize_message(const signal_message& mesg);
signal_message deserialize_message(std::string mesg);

namespace boost::serialization {
    template<class Archive, typename T>
    void serialize(Archive& ar, const crypto::secure_vector<T>& v, const unsigned int version) {
        boost::ignore_unused_variable_warning(version);
        ar& boost::serialization::base_object<const std::vector<T>>(v);
    }
} // namespace boost::serialization

#endif /* end of include guard: MESSAGE_H */
