#ifndef __BEARSSL_WRAPPER_H__
#define __BEARSSL_WRAPPER_H__
#include <stddef.h>
#include <stdint.h>

#include "BearSSL/inc/bearssl.h"

uint32_t sha256_uint32_t(const void *data, size_t len);
int gen_key_pair_curve25519(br_ec_public_key *pk, br_ec_private_key *sk);
int gen_key_pair_secp384r1(br_ec_public_key *pk, br_ec_private_key *sk);
void free_br_ec_public_key(br_ec_public_key *pk);
void free_br_ec_private_key(br_ec_private_key *sk);

#endif
