#ifndef KDF_H
#define KDF_H

#include <cstdint>
#include <array>
#include <cstddef>

void root_derive(std::array<std::byte, 32> root_key, std::array<std::byte, 32> dh_output, std::array<std::byte, 32> out_root, std::array<std::byte, 32> out_chain);
void chain_derive(std::array<std::byte, 32> chain_key, std::array<std::byte, 32> out_chain, std::array<std::byte, 32> out_message);

#endif
