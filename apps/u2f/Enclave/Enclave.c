#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "BearSSL/inc/bearssl.h"
#include "br_ec_key.h"
#include "common.h"
#include "sg.h"
#include "sg_common.h"
#include "stdfunc.h"
#include "uthash/include/uthash.h"
#include "x509.h"

//#define DEBUG 1
#define U2F_FILENAME "/tmp/.u2f.db"

typedef struct {
  uint8_t curve;
  uint8_t xlen;
  uint8_t x[BR_EC_KBUF_PRIV_MAX_SIZE];
} br_ec_skey;

typedef struct {
  uint8_t curve;
  uint8_t qlen;
  uint8_t q[BR_EC_KBUF_PUB_MAX_SIZE];
} br_ec_pkey;

typedef struct site_info_t_ {
  uint64_t key_handle;
  uint32_t counter;
  br_ec_skey user_private_key;
} site_info_t;

typedef struct {
  br_ec_pkey attest_pkey;
  br_ec_skey attest_skey;
  size_t cert_len;
  uint8_t cert[CERT_MAX_LEN];
  sg_ctx_t sg;
} u2fdev_ctx;

u2fdev_ctx device_ctx;

unsigned char private_key_buf[BR_EC_KBUF_PRIV_MAX_SIZE];
br_ec_private_key private_key = {.x = private_key_buf};
int guid;
char *hostname_list[] = {"baguette.rcs.uwaterloo.ca",
                         "mantou.rcs.uwaterloo.ca"};

static void add_site_to_device(uint64_t key_handle_dec,
                               br_ec_private_key *skey);
static int get_site(site_info_t **site, uint64_t key_handle);
static void hex_dec(const uint8_t *key_handle, uint64_t *dec);
static void gen_key_handle(br_ec_private_key *sk, unsigned char *buf,
                           size_t len);

static void prepare_new_site(site_info_t *site, br_ec_key *skey) {
  assert(skey->type == SKEY);
  memset(site, 0, sizeof(site_info_t));
  site->counter = 0;
  site->user_private_key.curve = skey->skey.curve;
  site->user_private_key.xlen = skey->skey.xlen;
  memcpy(site->user_private_key.x, skey->skey.x, skey->skey.xlen);
}

static void eprint_site(site_info_t *site) {
  edividerWithText("Site Info");
  eprintf("counter\t : %d\n", site->counter);
  eprintf("q len\t : %d\n", site->user_private_key.xlen);
  eprintf("q \t : %s\n",
          hexstring(site->user_private_key.x, site->user_private_key.xlen));
  edivider();
}

void print_site_info(const void *data) {
  site_info_t *site = (site_info_t *)data;
  eprintf("\tCounter : %d\n", site->counter);
  eprintf("\tQ len   : %d\n", site->user_private_key.xlen);
  eprintf("\tQ       : %s...\n\n", hexstring(site->user_private_key.x, 10));
}

static int init_new_device(const char *filename) {
  // eprintf("+ Generating device attestation key pair\n");
  br_ec_key pkey = BR_EC_KEY_INIT_PKEY;
  br_ec_key skey = BR_EC_KEY_INIT_SKEY;

  int ret = gen_key_pair_secp256r1(&pkey, &skey);
  if (ret) {
    eprintf("Error, gen_key_pair_secp256r1 failed with %d.\n", ret);
    exit(1); // TODO
  }

  memset(&device_ctx, 0, sizeof(device_ctx));

  device_ctx.attest_pkey.curve = pkey.pkey.curve;
  device_ctx.attest_pkey.qlen = pkey.pkey.qlen;
  memcpy(device_ctx.attest_pkey.q, pkey.pkey.q, pkey.pkey.qlen);

  device_ctx.attest_skey.curve = skey.skey.curve;
  device_ctx.attest_skey.xlen = skey.skey.xlen;
  memcpy(device_ctx.attest_skey.x, skey.skey.x, skey.skey.xlen);

  device_ctx.cert_len = CERT_MAX_LEN;

  // br_ec_key_free(&pkey);
  // br_ec_key_free(&skey);

  // eprintf("+ Generating self-signed X509 certificate of device attestation
  // key\n");
  cert_details_t details;
  strncpy(details.not_before, "190619163607Z", strlen("190619163607Z"));
  strncpy(details.not_after, "210831075959Z", strlen("210831075959Z"));
  strncpy(details.subj_common_name, "u2f device", strlen("u2f device"));
  strncpy(details.subj_org_name, "U2F Device", strlen("U2F Device"));
  strncpy(details.subj_cntry_name, "CA", strlen("CA"));

  uint8_t *cert_buf = NULL;
  ret = generate_self_signed_certificate(&cert_buf, &device_ctx.cert_len,
                                         &pkey.pkey, &pkey.pkey, &skey.skey,
                                         /*
                                         &device_ctx.attest_pkey.pkey,
                                         &device_ctx.attest_pkey.pkey,
                                         &device_ctx.attest_skey.skey,
                                         */
                                         details);
  if (ret) {
    eprintf("Error, generate_self_signed_certificate failed.\n");
    exit(1); // TODO
  }
  if (device_ctx.cert_len > CERT_MAX_LEN) {
    eprintf(
        "Error, generated certificate is too big - expected %d actual %d.\n",
        CERT_MAX_LEN, device_ctx.cert_len);
    exit(1);
  }
  memcpy(device_ctx.cert, cert_buf, device_ctx.cert_len);
  free(cert_buf);

  // eprintf("+ Initializing SG Context \n");
  //init_sg(&device_ctx.sg, filename);

  ret = 0;//add_sg(&device_ctx.sg, 0, (void *)&device_ctx,
               //sizeof(u2fdev_ctx) - sizeof(sg_ctx_t));
  if (!ret) {
    eprintf("Error, failed to add pair <0,device_ctx> to store.\n");
    exit(1);
  }

  ret = 1; // save_sg(&device_ctx.sg, filename);
  if (ret) {
    eprintf("%s : failed to save table\n");
    exit(1);
  }

#ifdef DEBUG_ENC
  edividerWithText("Device Attestation Keys");
  eprintf("Private Key\t : %s\n",
          hexstring(device_ctx.attest_skey.x, device_ctx.attest_skey.xlen));
  eprintf("Public Key\t : %s\n",
          hexstring(device_ctx.attest_pkey.q, device_ctx.attest_pkey.qlen));
  edivider();
#endif
}

void ecall_init_device(int uid) {
  guid = uid;
  int ret = 0; // load_sg(&device_ctx.sg, U2F_FILENAME);
  if (!ret) {
    eprintf("+ Loaded existing table\n"); // Entry with value 0 stores a
                                          // device_context, load that into
                                          // device_ctx
    u2fdev_ctx ctx;
    ret = 0; // find_sg(&device_ctx.sg, 0, (void *)&ctx, sizeof(u2fdev_ctx) -
             // sizeof(sg_ctx_t));
    if (!ret) {
      eprintf("Error, loaded table does not contain device context info\n");
      exit(1);
    }
    memcpy(&ctx, &device_ctx, sizeof(u2fdev_ctx) - sizeof(sg_ctx_t));
    memset(&ctx, 0, sizeof(u2fdev_ctx));
    return;
  }

  eprintf("+ Generating new table\n");
  init_new_device(U2F_FILENAME);
  return;
}

int ecall_get_cert(unsigned char *buf, size_t len) {
  memcpy(buf, device_ctx.cert, device_ctx.cert_len);
  return device_ctx.cert_len;
}

/*
 * P-256 NIST elliptic curve A.K.A secp256r1
 */
void ecall_generate_site_keys(unsigned char *key_handle, size_t key_handle_len,
                              unsigned char *public_key,
                              size_t public_key_len) {
  br_ec_key pkey = BR_EC_KEY_INIT_PKEY;
  br_ec_key skey = BR_EC_KEY_INIT_SKEY;
  unsigned char buf[br_sha256_SIZE] = {0};

  /* Generate key pair */
  int ret = gen_key_pair_secp256r1(&pkey, &skey);
  if (ret) {
    eprintf("Error, gen_key_pair_secp256r1 failed\n");
    exit(1); // TODO
  }
  assert(pkey.pkey.qlen == public_key_len);
  memcpy(public_key, pkey.pkey.q, pkey.pkey.qlen);

  /* Generate key handle */
  gen_key_handle(&skey.skey, buf, br_sha256_SIZE);
  assert(key_handle_len == br_sha256_SIZE);
  memcpy(key_handle, buf, key_handle_len);

  /* Add to kvstore */
  uint64_t kh;
  hex_dec(key_handle, &kh);

  site_info_t new_site;
  prepare_new_site(&new_site, &skey);

#ifdef DEBUG_ENC
  eprint_site(&new_site);
  eprintf("\t+ Adding <%lu, %s[...]> to table\n", kh, hexstring(&new_site, 10));
#endif
  ret = 0; // add_sg(&device_ctx.sg, kh, (void *)&new_site,
           // sizeof(site_info_t));
  if (!ret) {
    eprintf("Error, failed to add pair to store\n");
    exit(1);
  }

  ret = 1; // save_sg(&device_ctx.sg, U2F_FILENAME);
  if (ret) {
    eprintf("%s : failed to save table\n");
    exit(1);
  }

  //#ifdef DEBUG
  edividerWithText("New Site Info");
  eprintf("Public Key  (%lu) : %s...\n", public_key_len,
          hexstring(public_key, 10));
  eprintf("Private Key (%lu) : **********\n", skey.skey.xlen);
  eprintf("Key Handle       : %lu\n", kh);
  edivider();
  // eprint_site(&new_site);
  //#endif

  eprintf("+ SENDING update to %s\n", hostname_list[(guid + 1) % 2]);
  ret = 1; // send_update_sg(&device_ctx.sg, hostname_list[(guid+1)%2]);
#ifdef DEBUG_ENC
  if (ret) {
    eprintf("\t+ Failed to send update to %s\n", hostname_list[(guid + 1) % 2]);
  } else {
    eprintf("\t+ Successfully sent update\n");
  }
#endif

  // memcpy(private_key_buf, skey.skey.x, skey.skey.xlen);
  // private_key.xlen = skey.skey.xlen;
  // private_key.curve = skey.skey.curve;
  // br_ec_key_free(&pkey);
  // br_ec_key_free(&skey);
}

int ecall_generate_registration_signature(const unsigned char *key_handle,
                                          size_t key_handle_len,
                                          const char *data, size_t data_len,
                                          unsigned char *signature,
                                          size_t signature_len) {

  br_sha256_context hash_ctx;
  unsigned char buf[br_sha256_SIZE] = {0};

  br_sha256_init(&hash_ctx);
  br_sha256_update(&hash_ctx, data, data_len);
  br_sha256_out(&hash_ctx, buf);

  // Must pass br_ec_private_key to signing function
  br_ec_private_key skey;
  skey.curve = device_ctx.attest_skey.curve;
  skey.x = device_ctx.attest_skey.x;
  skey.xlen = device_ctx.attest_skey.xlen;

  int ret = br_ecdsa_i31_sign_asn1(&br_ec_all_m31, &br_sha256_vtable, buf,
                                   &skey, signature);

  return ret;
}

int ecall_generate_authentication_signature(const unsigned char *key_handle,
                                            size_t key_handle_len,
                                            const char *data, size_t data_len,
                                            unsigned char *signature,
                                            size_t signature_len) {
  br_sha256_context hash_ctx;
  unsigned char buf[br_sha256_SIZE] = {0};

  br_sha256_init(&hash_ctx);
  br_sha256_update(&hash_ctx, data, data_len);
  br_sha256_out(&hash_ctx, buf);

  uint64_t kh;
  site_info_t site;
  hex_dec(key_handle, &kh);
  int ret =
      0; // find_sg(&device_ctx.sg, kh, (void *)&site, sizeof(site_info_t));
  if (!ret) {
    eprintf("Error, entry with key %lu not found\n", kh);
    exit(1);
  }
#ifdef DEBUG_ENC
  eprint_site(&site);
#endif

  br_ec_private_key skey;
  skey.curve = site.user_private_key.curve;
  skey.x = site.user_private_key.x;
  skey.xlen = site.user_private_key.xlen;

  ret = br_ecdsa_i31_sign_asn1(&br_ec_all_m31, &br_sha256_vtable, buf, &skey,
                               signature);

  return ret;
}

uint32_t ecall_inc_and_get_site_counter(const unsigned char *key_handle,
                                        size_t key_handle_len) {
  site_info_t *site = NULL;
  uint8_t buf[1024];
  size_t buf_len = 1024;
  uint64_t kh;

  // Find value
  hex_dec(key_handle, &kh);
  int ret = 0; // find_sg(&device_ctx.sg, kh, buf, buf_len);
  site = (site_info_t *)buf;

  if (!ret) {
    eprintf("%s : failed to find key\n", __FUNCTION__);
    return -1;
  }

  site->counter += 1;
  uint32_t ctr = site->counter;

  // Delete pair and re-insert
  ret = 0; // remove_sg(&device_ctx.sg, kh);
  if (!ret) {
    eprintf("%s : failed to remove kv-pair\n");
    return -1;
  }

  ret = 0; // add_sg(&device_ctx.sg, kh, site, sizeof(site_info_t));
  if (!ret) {
    eprintf("%s : failed to add kv-pair\n");
    return -1;
  }

  // Save to file
  ret = 1; // save_sg(&device_ctx.sg, U2F_FILENAME);
  if (ret) {
    eprintf("%s : failed to save table\n");
    return -1;
  }

  return ctr;
}

int ecall_listen_updates() {
  eprintf("+ Listening for updates\n");
  return 0; // listen_updates_sg(&device_ctx.sg);
}

int ecall_send_update(const char *host) {
  eprintf("+ Sending updated to %s\n", host);
  // send_update_sg(&device_ctx.sg, host);
}

static void hex_dec(const uint8_t *key_handle, uint64_t *dec) {
  int base = 1;
  *dec = 0;
  for (int i = 3; i >= 0; --i) {
    uint8_t x = (key_handle[i] & 0x0F);
    uint8_t y = (key_handle[i] & 0xF0) >> 4;
    *dec += x * base;
    base *= 16;
    *dec += y * base;
    base *= 16;
  }
}

static void gen_key_handle(br_ec_private_key *sk, unsigned char *buf,
                           size_t len) {
  br_sha256_context hash_ctx;
  assert(len == br_sha256_SIZE);
  br_sha256_init(&hash_ctx);
  br_sha256_update(&hash_ctx, sk->x, sk->xlen);
  br_sha256_out(&hash_ctx, buf);
}
