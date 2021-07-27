#ifndef __WOLFSSL_HELPER_H__
#define __WOLFSSL_HELPER_H__

#include "wolfssl/wolfcrypt/rsa.h"

void sha256_rsa_pubkey(unsigned char hash[SHA256_DIGEST_SIZE], RsaKey* key);

#endif
