#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stdbool.h>
#include <stdlib.h>

void encrypt(const uint8_t *const message, const size_t mesg_len, const uint8_t key[], const uint8_t *const aad, const size_t aad_len, uint8_t *const ciphertext, uint8_t tag[]);
bool decrypt(const uint8_t *const ciphertext, const size_t cipher_len, const uint8_t tag[], const uint8_t key[], const uint8_t *const aad, const size_t aad_len, uint8_t *const plaintext);

#endif
