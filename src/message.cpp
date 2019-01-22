#include <sstream>
#include <string>

#include "crypto.h"
#include "message.h"

std::string serialize_message(const signal_message& mesg) {
    std::stringstream ss;

    //First, encode the header
    if (mesg.header.index() == 0) {
        ss << 0 << ';';
        //Regular message header
        const auto header = std::get<0>(mesg.header);
        ss << crypto::base64_encode(header.dh_public_key) << ';';
        ss << header.prev_chain_len << ';';
        ss << header.message_num << ';';
    } else {
        ss << 1 << ';';
        //Initial message header
        const auto header = std::get<1>(mesg.header);
        ss << crypto::base64_encode(header.identity_key) << ';';
        ss << crypto::base64_encode(header.ephemeral_key) << ';';

        if (header.remote_one_time_public_key.has_value()) {
            ss << crypto::base64_encode(*header.remote_one_time_public_key) << ';';
        }
    }

    //Then just base64 encode the message and AAD
    ss << crypto::base64_encode(mesg.message) << ';';
    ss << crypto::base64_encode(mesg.aad);

    return ss.str();
}

signal_message deserialize_message(std::string mesg) {
    try {
        signal_message out;

        size_t delim_pos = mesg.find_first_of(';');
        if (delim_pos != 1) {
            //Delimiter either nonexistant or in invalid position
            throw std::runtime_error("1 Corrupted message serialization");
        }

        int header_type = std::stoi(mesg, nullptr, 10);

        if (header_type < 0 || header_type > 1) {
            //Number is out of range
            throw std::runtime_error("2 Corrupted message serialization");
        }

        //Erase the header number and the first delimiter
        mesg.erase(0, 2);

        delim_pos = mesg.find_first_of(';');
        if (delim_pos != 44) {
            //Next member is always a public key
            //44 bytes is the length of 32 bytes base64 encoded
            throw std::runtime_error("3 Corrupted message serialization");
        }

        const auto pub_key = crypto::base64_decode(std::string_view{mesg.c_str(), 44});

        if (header_type == 0) {
            //Regular message header
            message_header h;
            memcpy(h.dh_public_key.data(), pub_key.data(), pub_key.size());

            //Erase the public key and its delimiter
            mesg.erase(0, 45);

            h.prev_chain_len = std::stoi(mesg, nullptr, 10);

            mesg.erase(0, mesg.find_first_of(';') + 1);

            h.message_num = std::stoi(mesg, nullptr, 10);

            mesg.erase(0, mesg.find_first_of(';') + 1);

            out.header = h;
        } else {
            //Initiation message header
            initial_message_header h;
            memcpy(h.identity_key.data(), pub_key.data(), pub_key.size());

            //Erase the public key and its delimiter
            mesg.erase(0, 45);

            delim_pos = mesg.find_first_of(';');
            if (delim_pos != 44) {
                //44 bytes is the length of 32 bytes base64 encoded
                throw std::runtime_error("4 Corrupted message serialization");
            }

            const auto eph_key = crypto::base64_decode(std::string_view{mesg.c_str(), 44});
            memcpy(h.ephemeral_key.data(), eph_key.data(), eph_key.size());

            //Erase the public key and its delimiter
            mesg.erase(0, 45);

            size_t delim_count = std::count(mesg.begin(), mesg.end(), ';');

            if (delim_count < 1 || delim_count > 2) {
                //Delimiter count outside of expected range
                throw std::runtime_error("5 Corrupted message serialization");
            }

            if (delim_count == 2) {
                //We have an optional one-time key
                delim_pos = mesg.find_first_of(';');
                if (delim_pos != 44) {
                    //44 bytes is the length of 32 bytes base64 encoded
                    throw std::runtime_error("6 Corrupted message serialization");
                }
                const auto one_key = crypto::base64_decode(std::string_view{mesg.c_str(), 44});
                crypto::public_key one_time;
                memcpy(one_time.data(), one_key.data(), one_key.size());
                h.remote_one_time_public_key = std::move(one_time);

                //Erase the public key and its delimiter
                mesg.erase(0, 45);
            }

            out.header = h;
        }

        delim_pos = mesg.find_first_of(';');

        const auto tmp_mesg = crypto::base64_decode(std::string_view{mesg.c_str(), delim_pos});
        //memcpy(out.message.data(), tmp_mesg.data(), tmp_mesg.size());

        out.message.assign(tmp_mesg.begin(), tmp_mesg.end());

        mesg.erase(0, delim_pos + 1);

        const auto tmp_aad = crypto::base64_decode(std::string_view{mesg});
        //memcpy(out.aad.data(), tmp_aad.data(), tmp_aad.size());
        out.aad.assign(tmp_aad.begin(), tmp_aad.end());

        return out;
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::runtime_error&) {
        throw;
    } catch (...) {
        //throw std::runtime_error("7 Corrupted message serialization");
        throw;
    }
}
