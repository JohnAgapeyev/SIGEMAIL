#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include "test.h"
#include "gen_x.h"
#include "crypto_hash_sha512.h"
#include "keygen.h"
#include "curve_sigs.h"
#include "xeddsa.h"
#include "crypto_additions.h"
#include "ge.h"
#include "utility.h"
#include "gen_crypto_additions.h"
#include "curve25519-donna.h"

void testing(void) {
    printf("This is a thing that has run\n");

    const unsigned char *message = (const unsigned char *) "This is a test of things and stuff";

    unsigned char sig[64];
    unsigned char sig_2[96];
    unsigned char random[32];
    unsigned char vrf[32];

    RAND_bytes(random, 32);

    unsigned char client_pk[32];
    unsigned char client_sk[32];

    RAND_bytes(client_sk, 32);

    sc_clamp(client_sk);
    curve25519_keygen(client_pk, client_sk);

    int x = 0;

    if ((x = generalized_xeddsa_25519_sign(sig, client_sk, message, strlen((char *) message), random, NULL, 0)) != 0) {
        printf("Failed first sign\n");
        printf("%d\n", x);
    }
    printf("Passed first sign\n");

    if ((x = generalized_xeddsa_25519_verify(sig, client_pk, message, strlen((char *) message), NULL, 0)) != 0) {
        printf("Failed first verify\n");
        printf("%d\n", x);
    }
    printf("Passed first verify\n");

    if ((x = generalized_xveddsa_25519_sign(sig_2, client_sk, message, strlen((char *) message), random, NULL, 0)) != 0) {
        printf("Failed second sign\n");
        printf("%d\n", x);
    }
    printf("Passed second sign\n");

    if ((x = generalized_xveddsa_25519_verify(vrf, sig_2, client_pk, message, strlen((char *) message), NULL, 0)) != 0) {
        printf("Failed second verify\n");
        printf("%d\n", x);
    }
    printf("Passed second verify\n");

    unsigned char client_pk_1[32];
    unsigned char client_sk_1[32];

    RAND_bytes(client_sk_1, 32);

    sc_clamp(client_sk_1);
    curve25519_keygen(client_pk_1, client_sk_1);

    uint8_t shared[32];

    curve25519_donna(shared, client_sk, client_pk_1);

    printf("Passed Diffie Hellman verify\n");
}
