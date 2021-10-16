#ifndef __BR_EC_KEY_H__
#define __BR_EC_KEY_H__

#include "BearSSL/inc/bearssl.h"
//#include "key.pb-c.h"

typedef enum {PKEY, SKEY} br_ec_key_type;

typedef struct {
	int type;
	union {
		br_ec_public_key pkey;
		br_ec_private_key skey;
	};
} br_ec_key;

#define BR_EC_KEY_INIT_PKEY {.type = PKEY, .pkey.q = NULL}
#define BR_EC_KEY_INIT_SKEY {.type = SKEY, .skey.x = NULL}

int gen_key_pair_secp256r1(br_ec_key *pkey, br_ec_key *skey);
void br_ec_key_free(br_ec_key *key);
void br_ec_key_print(br_ec_key *key);

/*
void br_ec_key_serial(br_ec_key *key, unsigned char **buf, size_t *len);
int br_ec_key_deserial(br_ec_key *key, unsigned char *buf, size_t len);
int br_ec_key_gen_curve25519(br_ec_key *pkey, br_ec_key *skey);
int br_ec_key_gen_secp384r1(br_ec_key *pkey, br_ec_key *skey);
int br_ec_key_gen_static(br_ec_key *pkey, br_ec_key *skey);


*/

#endif
