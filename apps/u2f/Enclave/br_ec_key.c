#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "br_ec_key.h"
#include "BearSSL/inc/bearssl.h"
#include "stdfunc.h"

#define DEBUG 1
/*


#include "bearssl_wrapper.h"
#include "memory_wrapper.h"
#include "keys.h"

static int gen_key_pair(br_ec_public_key *pk, br_ec_private_key *sk, int curve, void *impl);
static void br_ec_key_copyout(Key *msg, br_ec_key *key);
static void br_ec_key_copyin(Key *msg, br_ec_key *key);

void 
br_ec_key_serial(br_ec_key *key, unsigned char **buf, size_t *len)
{
	Key msg = KEY__INIT;

	*buf = nullptr;
	*len = 0;

	br_ec_key_copyout(&msg, key);

	*len = key__get_packed_size (&msg);

	assert(*len < MSG_LEN_MAX);

	*buf = (unsigned char *)malloc (*len);                       
	key__pack (&msg, *buf); 

	free(msg.kbuf);
}

int 
br_ec_key_deserial(br_ec_key *key, unsigned char *buf, size_t len)
{
	Key *msg;
	//size_t msg_len = read_buffer (len, buf);
	assert(len < MSG_LEN_MAX);
	
	msg = key__unpack (NULL, len, buf);

	if (msg == NULL) { // Something failed
		printf("Error unpacking incoming message\n");
		return 1;
	}

	br_ec_key_copyin(msg, key);	

	key__free_unpacked(msg,NULL);	
  
  	return 0;
}

void
br_ec_key_copyout(Key *msg, br_ec_key *key)
{
	msg->type = key->type;
	

	if (key->type == PKEY) 
	{
		msg->curve = key->pkey.curve;
		msg->n_kbuf = key->pkey.qlen;
		msg->kbuf = (int *)malloc(sizeof(int) * msg->n_kbuf);
		for(int i=0; i<msg->n_kbuf; ++i)
			msg->kbuf[i] = key->pkey.q[i];
	} else {
		msg->curve = key->skey.curve;
		msg->n_kbuf = key->skey.xlen;
		msg->kbuf = (int *)malloc(sizeof(int) * msg->n_kbuf);
		for(int i=0; i<msg->n_kbuf; ++i)
			msg->kbuf[i] = key->skey.x[i];
	}
}

void
br_ec_key_copyin(Key *msg, br_ec_key *key)
{
    key->type = msg->type;
	
	if (key->type == PKEY) {
		key->pkey.curve = msg->curve;
		key->pkey.qlen = msg->n_kbuf; 
		key->pkey.q = (unsigned char *)malloc(key->pkey.qlen);
		for(int i=0; i<key->pkey.qlen; ++i)
			key->pkey.q[i] = msg->kbuf[i];
		
	} else {
		key->skey.curve = msg->curve;
		key->skey.xlen = msg->n_kbuf; 
		key->skey.x = (unsigned char *)malloc(key->skey.xlen);
		for(int i=0; i<key->skey.xlen; ++i)
			key->skey.x[i] = msg->kbuf[i];

	}
}
*/

static int gen_key_pair(br_ec_public_key *pk, br_ec_private_key *sk, int curve, void *impl);

void
br_ec_key_free(br_ec_key *key) {
    if (key->type == PKEY && key->pkey.q != NULL) {
    	memset(key->pkey.q, 0, BR_EC_KBUF_PRIV_MAX_SIZE);
    	free(key->pkey.q);
    	key->pkey.q = NULL;
    }
    else if (key->type == SKEY && key->skey.x != NULL) {
    	memset(key->skey.x , 0, BR_EC_KBUF_PUB_MAX_SIZE);
    	free(key->skey.x );
    	key->skey.x  = NULL;
    }
}


int
gen_key_pair_secp256r1(br_ec_key *pkey, br_ec_key *skey)
{
    int curve = BR_EC_secp256r1;
    const br_ec_impl *impl = &br_ec_p256_m15;
    int ret = gen_key_pair(&pkey->pkey, &skey->skey, curve, (void *)impl);
    return ret;
}


/*
 * TODO: WARNING: this allocated memory for the key, instead we should have a struct
 * with a fixed buffer that is filled in 
 */
static int
gen_key_pair(br_ec_public_key *pk, br_ec_private_key *sk, int curve, void *impl)
{
    br_hmac_drbg_context rng_ctx;
    unsigned char *kbuf_priv = NULL;
    unsigned char *kbuf_pub = NULL;

    br_hmac_drbg_init(&rng_ctx, &br_sha256_vtable, "seed for EC keygen", 18);
    //inject additional seed bytes: br_hmac_drbg_update(&rng_ctx, name, strlen(name));
    kbuf_priv = (uint8_t *)malloc(BR_EC_KBUF_PRIV_MAX_SIZE);
    memset(kbuf_priv, 0, BR_EC_KBUF_PRIV_MAX_SIZE);

    int ret = br_ec_keygen(&rng_ctx.vtable, (const br_ec_impl *)impl, sk, kbuf_priv, curve);
    if (ret == 0) {
#ifdef DEBUG
        eprintf("Error, br_ec_keygen failed\n");
#endif
        goto cleanup;
    }

    sk->curve = curve;
    kbuf_pub = (uint8_t *)malloc(BR_EC_KBUF_PUB_MAX_SIZE);
    memset(kbuf_pub, 0, BR_EC_KBUF_PUB_MAX_SIZE);

    ret = br_ec_compute_pub((const br_ec_impl *)impl, pk, kbuf_pub, sk);
    if (ret == 0) {
#ifdef DEBUG
        eprintf("Error, br_ec_compute_pub failed\n");
#endif
        goto cleanup;
    }
/*
#ifdef DEBUG
    eprintf("Public Key (%lu): %s\n", pk->qlen, hexstring(pk->q, pk->qlen));
    eprintf("Private Key (%lu): %s\n", sk->xlen, hexstring(sk->x, sk->xlen));
#endif
*/
    return 0;

cleanup:
    if (kbuf_priv != NULL) {
    	memset(kbuf_priv, 0, BR_EC_KBUF_PRIV_MAX_SIZE);
    	free(kbuf_priv);
    	kbuf_priv = NULL;
    }

    if (kbuf_pub != NULL) {
    	memset(kbuf_pub, 0, BR_EC_KBUF_PUB_MAX_SIZE);
    	free(kbuf_pub);
    	kbuf_pub = NULL;
    }
    return 1;
}

void br_ec_key_print(br_ec_key *key)
{
	int type = key->type;
	eprintf("Type : \t%s\n", (type == PKEY) ? "PKEY" : "SKEY");
	switch (type) {
		case PKEY:
			eprintf("q len : \t%d\n", key->pkey.qlen);
			eprintf("q : \t%s\n", hexstring(key->pkey.q, key->pkey.qlen));
			break;
		case SKEY:
			eprintf("x len : \t%d\n", key->skey.xlen);
			eprintf("x : \t%s\n", hexstring(key->skey.x, key->skey.xlen));
			break;
		default:
			break;
	}
	

}



