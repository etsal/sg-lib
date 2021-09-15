#include <assert.h>

#include "config.h"
#include "errlist.h"
#include "keycert.pb-c.h"
#include "librassl/attester.h"
#include "sg.h"
#include "sg.pb-c.h"
#include "sg_common.h"
#include "sg_t.h" // ocalls
#include "sg_util.h"
#include "store.pb-c.h"
#include "wolfssl_enclave.h"

#include "sg_log.h"

extern ra_tls_options_t global_opts;

#define DEBUG_SG 1

static int serialize_and_seal_sg(sg_ctx_t *ctx, const char *filepath);
static int unseal_and_deserialize_sg(sg_ctx_t *ctx, const char *filepath);
static void init_keycert(sg_ctx_t *ctx);
static configuration *parse_config(const char *config, size_t config_len);
 
static configuration *parse_config(const char *config, size_t config_len) {
  int cur = 0;
  configuration *c = malloc(sizeof(configuration));
  c->found_ips = 0;

  int i = 0;
  while (cur < config_len && i < MAX_NODES) {
    if (config + cur == '\0')
      break;
    c->ips[i++] = strndup(config + cur, strlen(config + cur));
    cur += strlen(config + cur) + 1;
#ifdef DEBUG_SG
    eprintf("\t+ (%s) Found: %s\n", __FUNCTION__, c->ips[i - 1]);
#endif
  }
  if (!(i < MAX_NODES)) {
#ifdef DEBUG_SG
    eprintf("\t+ (%s) WARNING: More than %d nodes found in config\n",
            __FUNCTION__, MAX_NODES);
#endif
  }

  c->found_ips = i;
  return c;
}

static void init_keycert(sg_ctx_t *ctx) {
#ifdef DEBUG_SG
//  eprintf("\t+ (%s) Creating RA-TLS Attestation Keys and Certificate\n", __FUNCTION__);
#endif

  ctx->kc.der_key_len = DER_KEY_LEN;
  ctx->kc.der_cert_len = DER_CERT_LEN;

  create_key_and_x509(ctx->kc.der_key, &ctx->kc.der_key_len, ctx->kc.der_cert,
                      &ctx->kc.der_cert_len, &global_opts);
}

/*
 * init_sg()
 * Ideally we call init_db to do the database
 * initialization but we save the kv-store and
 * the attestation information together
 * so we call them here instead
 */
void init_sg(sg_ctx_t *ctx, void *config, size_t config_len) {
  configuration *c;
  int ret;

  memset(ctx, 0, sizeof(sg_ctx_t));
  sgx_thread_mutex_init(&ctx->table_lock, NULL);

#ifdef __USE_POLICY__
  next_uid = 0;
#endif

  // Deserialize configuration structure and save it to the sgx context
  c = unpack_config(config, config_len);
  ctx->config = c;
  assert(c != NULL && verify_config(config));

  init_log(ctx->config->log_file);
  ret = write_blob_log("Initializing sg\n");
  if (ret) {
    eprintf("\t+ (%s) Failed to initialize log (%d)... exiting\n", __FUNCTION__,
            ret);
    assert(1);
  }

  // Attempts to unseal the sealed sgx ctx saved in
  // ctx->config->sealed_sg_ctx_file
  ret = unseal_and_deserialize_sg(ctx, NULL);
  if (ret) {
#ifdef DEBUG_SG
    eprintf("\t+ (%s) Failed to unseal_and_deserialize(%s) with ret=%x!\n",
            __FUNCTION__, ctx->config->sealed_sg_ctx_file, ret);
#endif
    // Todo: decide whether or not to do brandnew init
    init_new_sg(ctx);
  } else {
#ifdef DEBUG_SG
    eprintf("\t+ (%s) Successfully unsealed saved context %s!\n", __FUNCTION__,
            ctx->config->sealed_sg_ctx_file);
#endif
    // Todo: Check if each item in the saved context was loaded
    // Verify keycert was loaded
    if (!verify_keycert(&ctx->kc)) {
      init_keycert(ctx);
    }

    // Verify kvstore
    if (!is_empty_store(&ctx->table)) {
      init_store(&ctx->table, 1); // TODO: specify UID
      //init_new_db(&ctx->db);
    }

    eprintf("\t+ (%s) Successfully verified keycert and db\n", __FUNCTION__);
  }

#ifdef DEBUG_SG
  eprintf("\t+ (%s) Setting up network stuff\n", __FUNCTION__);
#endif

  init_connections(ctx);
  init_ratls();
  init_ratls_server(&ctx->ratls, &ctx->kc);

#ifdef DEBUG_SG
  eprintf("\t+ (%s) Completed initialization!\n", __FUNCTION__);
#endif
}

/* init_new_sg
 * Creates new keypair, attestation certificate and empty database
 * optionally set wolfssl debugging
 * @param ctx
 */
void init_new_sg(sg_ctx_t *ctx) {
  /*
  #ifdef DEBUG_SG
      eprintf("+ Turning on wolfssl debugging\n");
      enc_wolfSSL_Debugging_ON();
  #endif
  */

#ifdef DEBUG_SG
  eprintf("\t+ (%s) Initializing new sg_ctx ... \n", __FUNCTION__);
#endif

  init_keycert(ctx);
  init_store(&ctx->table, 1); //TODO: specify uid 
  //init_new_db(&ctx->db);

#ifdef DEBUG_SG
  eprintf("\t+ (%s) Initializing new sg_ctx ... complete\n", __FUNCTION__);
 // eprintf("\t+ (%s) Completed initialization of new sg_ctx!\n", __FUNCTION__);
#endif
}

/* 1 on error, 0 on success */
int put_u64_sg(sg_ctx_t *ctx, uint64_t key, const void *value, size_t len) {
  char key_buf[22];
  int ret;
  if (iota_u64(key, key_buf, 22) == NULL)
    return 1;
  ret = put_store(&ctx->table, key_buf, value, len);
  return ret;
}

int get_u64_sg(sg_ctx_t *ctx, uint64_t key, void **value, size_t *len) {
  char key_buf[22];
  int ret;
  if (iota_u64(key, key_buf, 22) == NULL)
    return 1;
  ret = get_store(&ctx->table, key_buf, value, len);
  return ret;
}

/* 1 on error, 0 on success */
int put_sg(sg_ctx_t *ctx, const char *key, const void *value, size_t len) {
  int ret = put_store(&ctx->table, key, value, len);
  gen_log_msg(SG_PUT, key, ret);
#ifdef DEBUG_SG
/*
if (ret) {
    eprintf("\t+ (%s) Failed to 'put'  entry with key %s!\n", __FUNCTION__, key);
  } else {
    eprintf("\t+ (%s) Successfully 'put' entry with key %s!\n", __FUNCTION__, key);
  }
*/
#endif
  return ret;
}

int get_sg(sg_ctx_t *ctx, const char *key, void **value, size_t *len) {
  int ret = get_store(&ctx->table, key, value, len);
  gen_log_msg(SG_GET, key, ret);
#ifdef DEBUG_SG
/*
if (ret) {
    eprintf("\t+ (%s) Failed to 'get'  entry with key %s!\n", __FUNCTION__, key);
  } else {
    eprintf("\t+ (%s) Successfully 'get' entry with key %s!\n", __FUNCTION__, key);
  }
*/
#endif
  return ret;
}

int search_sg(sg_ctx_t *ctx,  const char *regex, char **key, void **value, size_t *len) {
  int ret = search_store(&ctx->table, regex, key, value, len);
  return ret;
}

int remove_sg(sg_ctx_t *ctx, uint64_t key) { return 0; }

int count_sg(sg_ctx_t *ctx) { return 0; }

int save_sg(sg_ctx_t *ctx, const char *filepath) {
  int ret = serialize_and_seal_sg(ctx, filepath);
  gen_log_msg(SG_SAVE, " " , ret);
  return ret;
}

int load_sg(sg_ctx_t *ctx, const char *filepath) {
  int ret = unseal_and_deserialize_sg(ctx, filepath);
  return ret;
}

void print_sg(sg_ctx_t *ctx, void (*format)(const void *data)) {
//  db_print(&ctx->db, format);
}


/* get_update_size Returns size of update in bytes
 * also creates and stores the update to the ctx 
 *
 */
int get_update_size(sg_ctx_t *ctx) {

  if (is_empty_store(&ctx->table)) {
    ctx->update_buf_len = 0;
  }
  else {
    free(ctx->update_buf);
    ctx->update_buf = NULL;
    serialize_store(&ctx->table, &ctx->update_buf, &ctx->update_buf_len);
  }
  return ctx->update_buf_len;

}

void get_update(sg_ctx_t *ctx, uint8_t *buf, size_t len) {
  if (len < ctx->update_buf_len) {
    memset(buf, 0, len);
    return;
  }
  if (ctx->update_buf_len > 0) {
    memcpy(buf, ctx->update_buf, ctx->update_buf_len);
  }
}

static int serialize_and_seal_sg(sg_ctx_t *ctx, const char *filepath) {
  const char *fp = filepath;
  if (fp == NULL)
    fp = ctx->config->sealed_sg_ctx_file;

  StateSg state = STATE_SG__INIT;
  state.kc = malloc(sizeof(Keycert));
  state.t = malloc(sizeof(Table));
  keycert__init(state.kc);
  table__init(state.t);
  protobuf_pack_keycert(&ctx->kc, state.kc);
  protobuf_pack_store(&ctx->table, state.t);

  size_t len = state_sg__get_packed_size(&state);
  uint8_t *buf = malloc(len);
  state_sg__pack(&state, buf);
  int ret = seal(fp, buf, len);

  protobuf_free_packed_keycert(state.kc);
  protobuf_free_packed_store(state.t);
  free(state.kc);
  free(state.t);
  free(buf);

  return ret;
}

/* unseal_and_deserialize
 * @param ctx Initialized context
 * @param filepath The filepath to use, if NULL will use
 * ctx->config->sealed_sg_ctx_file
 *
 * 0 on success, >0 on failure from errlist.h
 */
static int unseal_and_deserialize_sg(sg_ctx_t *ctx, const char *filepath) {
  size_t len = 0;
  uint8_t *buf = NULL;
  int ret;
  const char *fp = filepath;

  if (fp == NULL) {
    fp = ctx->config->sealed_sg_ctx_file;
#ifdef DEBUG_SG
    if (fp == NULL)
      eprintf("\t+ (%s) ABORTING fp == NULL\n", __FUNCTION__);
#endif
    assert(fp != NULL);
  }
  ret = unseal(fp, &buf, &len);

#ifdef DEBUG_SG
  // eprintf("\t+ (%s) unseal complete with ret = 0x%x!\n", __FUNCTION__, ret);
#endif

  if (ret) {
    return ret;
  }

  StateSg *state = NULL;
  state = state_sg__unpack(NULL, len, buf);
  if (state == NULL) {
    return ER_PROTOBUF;
  }

  protobuf_unpack_store(&ctx->table, state->t);
  protobuf_unpack_keycert(&ctx->kc, state->kc);

  table__free_unpacked(state->t, NULL);
  // keycert__free_unpacked(state->kc, NULL);
  // state_sg__free_unpacked(state, NULL);

#ifdef DEBUG_SG
  // eprintf("\t\t+ (%s) Complete!\n", __FUNCTION__);
#endif

  return 0;
}

