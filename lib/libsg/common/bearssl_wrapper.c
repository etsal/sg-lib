#include "bearssl_wrapper.h"
#include "sg_common.h"
#include "xmem.h"

static int gen_key_pair(
    br_ec_public_key *pk, br_ec_private_key *sk, int curve, void *impl);

uint32_t
sha256_uint32_t(const void *data, size_t len)
{
	uint32_t out = 0;
	uint8_t output[br_sha256_SIZE];
	memset(output, 0, br_sha256_SIZE);

	br_sha256_context sc;
	br_sha256_init(&sc);
	br_sha256_update(&sc, data, len);
	br_sha256_out(&sc, (void *)output);

	memcpy(&out, output, sizeof(uint32_t));

	return out;
}

int
gen_key_pair_curve25519(br_ec_public_key *pk, br_ec_private_key *sk)
{
	int curve = BR_EC_curve25519;
	const br_ec_impl *impl = &br_ec_c25519_i15;
	int ret = gen_key_pair(pk, sk, curve, (void *)impl);
	return ret;
}

int
gen_key_pair_secp384r1(br_ec_public_key *pk, br_ec_private_key *sk)
{
	int curve = BR_EC_secp384r1;
	const br_ec_impl *impl = &br_ec_all_m31;
	int ret = gen_key_pair(pk, sk, curve, (void *)impl);
	return ret;
}

void
free_br_ec_public_key(br_ec_public_key *pk)
{
	xfree(pk->q);
}

void
free_br_ec_private_key(br_ec_private_key *sk)
{
	xfree(sk->x);
}
/* Helpers */

/*
 * @return : 1 on succes, 0 otherwise
 */
int
gen_key_pair(br_ec_public_key *pk, br_ec_private_key *sk, int curve, void *impl)
{
	br_hmac_drbg_context rng_ctx;
	unsigned char *kbuf_priv = NULL;
	unsigned char *kbuf_pub = NULL;

	br_hmac_drbg_init(
	    &rng_ctx, &br_sha256_vtable, "seed for EC keygen", 18);
	// inject additional seed bytes: br_hmac_drbg_update(&rng_ctx, name,
	// strlen(name));

	kbuf_priv = (uint8_t *)xmalloc(BR_EC_KBUF_PRIV_MAX_SIZE);
	memset(kbuf_priv, 0, BR_EC_KBUF_PRIV_MAX_SIZE);
	if (br_ec_keygen(&rng_ctx.vtable, (const br_ec_impl *)impl, sk,
		kbuf_priv, curve) == 0) {
#if DEBUG
		eprintf("Error, br_ec_keygen failed\n");
#endif
		goto cleanup;
	}

	sk->curve = curve;

	kbuf_pub = (uint8_t *)xmalloc(BR_EC_KBUF_PUB_MAX_SIZE);
	memset(kbuf_pub, 0, BR_EC_KBUF_PUB_MAX_SIZE);
	if (br_ec_compute_pub((const br_ec_impl *)impl, pk, kbuf_pub, sk) ==
	    0) {
#if DEBUG
		eprintf("Error, br_ec_compute_pub failed\n");
#endif
		goto cleanup;
	}

#if DEBUG
	printf("Public Key (%lu): %s\n", pk->qlen, hexstring(pk->q, pk->qlen));
	printf("Private Key (%lu): %s\n", sk->xlen, hexstring(sk->x, sk->xlen));
#endif

	return 1;

cleanup:
	if (kbuf_priv == NULL)
		ZERO_AND_FREE(kbuf_priv, BR_EC_KBUF_PRIV_MAX_SIZE);

	if (kbuf_pub == NULL)
		ZERO_AND_FREE(kbuf_pub, BR_EC_KBUF_PUB_MAX_SIZE);

	return 0;
}
