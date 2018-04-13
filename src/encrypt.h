#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdbool.h>
#include <stdlib.h>

void encrypt(const uint8_t *const restrict message, const size_t mesg_len, const uint8_t key[static const restrict 32], const uint8_t *const restrict aad, const size_t aad_len, uint8_t *const restrict ciphertext, uint8_t tag[static const restrict 16]);
bool decrypt(const uint8_t *const restrict ciphertext, const size_t cipher_len, const uint8_t tag[static const restrict 16], const uint8_t key[static const restrict 32], const uint8_t *const restrict aad, const size_t aad_len, uint8_t *const restrict plaintext);

#endif
