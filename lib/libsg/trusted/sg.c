#include "sg.h"
#include "keycert.pb-c.h"
#include "librassl/attester.h"
#include "sg.pb-c.h"
#include "sg_common.h"
#include "sg_t.h" // ocalls
#include "sg_util.h"
#include "store.pb-c.h"
#include "wolfssl_enclave.h"
#include "config.h"

extern ra_tls_options_t global_opts;

#define DEBUG_SG 1

static int serialize_and_seal_sg(sg_ctx_t *ctx);
static int unseal_and_deserialize_sg(sg_ctx_t *ctx);
static char *iota_u64(uint64_t value, char *str, size_t len);

const char db_filename[] = "/opt/instance/sg.db";
const char policy_filename[] = "/opt/instance/policy.txt";

static char *iota_u64(uint64_t value, char *str, size_t len) {
  uint64_t tmp = value;
  int count = 0;

  while (1) {
    count++;
    tmp = tmp / 10;
    if (!tmp)
      break;
  }

  if (count > len)
    return NULL;
  str[count] = '\0';

  tmp = value;
  for (int i = 0; i < count; ++i) {
    int leftover = tmp % 10;
    tmp = tmp / 10;
    str[count - (i + 1)] = (char)leftover + 48;
  }
  return str;
}

static configuration *parse_config(const char *config, size_t config_len) {
  int cur = 0;
  configuration *c =  malloc(sizeof(configuration)); 
  c->found_ips = 0;

  int i = 0;
  while(cur < config_len && i < MAX_NODES) {
    if (config + cur == '\0') break;
    c->ips[i++] = strndup(config + cur, strlen(config + cur));        
    cur += strlen(config + cur) + 1;
#ifdef DEBUG_SG
    eprintf("\t+ (%s) Found: %s\n", __FUNCTION__, c->ips[i-1]);
#endif
  }
  if (!(i < MAX_NODES)) {
#ifdef DEBUG_SG
      eprintf("\t+ (%s) WARNING: More than %d nodes found in config\n", __FUNCTION__, MAX_NODES);
#endif
  }

  c->found_ips = i;
  return c;
}

/*
 * init_sg()
 * Ideally we call init_db to do the database
 * initialization but we save the kv-store and
 * the attestation information together
 * so we call them here instead
 */
void init_sg(sg_ctx_t *ctx, void *config, size_t config_len) {

  int ret; 
  configuration *c = unpack_config(config, config_len);
  assert(c != NULL);
  assert(verify_config(config));
  ctx->config = c;

  // Retrieve KC

  // Retrieve database file name from config
  strcpy(ctx->db.db_filename, c->database_file); 
  ret = unseal_and_deserialize_sg(ctx);
  if (ret) {
#ifdef DEBUG_SG
    eprintf("\t+ (%s) Database failed to load from %s, db is not set\n",
            __FUNCTION__, ctx->db.db_filename);
#endif
    init_new_sg(ctx);
  } else {
#ifdef DEBUG_SG
    eprintf("\t+ (%s) Database successfully loaded from %s\n", __FUNCTION__,
            ctx->db.db_filename);
#endif
  }
#ifdef DEBUG_SG
  eprintf("\t+ (%s) Finishing up initialization\n", __FUNCTION__);
#endif
  init_connections(ctx);
  init_ratls();
  init_ratls_server(&ctx->ratls, &ctx->kc);
#ifdef DEBUG_SG
  eprintf("\t+ (%s) Completed initialization of new sg_ctx!\n", __FUNCTION__);
#endif
}

/* init_new_sg
 * Creates new keypair, attestation certificate and empty database
 * optionally set wolfssl debugging
 * @param ctx
 */
void init_new_sg(sg_ctx_t *ctx) {
  ctx->kc.der_key_len = DER_KEY_LEN;
  ctx->kc.der_cert_len = DER_CERT_LEN;
/*
#ifdef DEBUG_SG
    eprintf("+ Turning on wolfssl debugging\n");
    enc_wolfSSL_Debugging_ON();
#endif
*/
#ifdef DEBUG_SG
  eprintf("\t+ (%s) Creating RA-TLS Attestation Keys and Certificate\n",
          __FUNCTION__);
#endif
  create_key_and_x509(ctx->kc.der_key, &ctx->kc.der_key_len, ctx->kc.der_cert,
                      &ctx->kc.der_cert_len, &global_opts);

#ifdef DEBUG_SG
  eprintf("\t+ (%s) Initializing Key Value Store ...\n", __FUNCTION__);
#endif
  init_new_db(&ctx->db, ctx->db.db_filename);

#ifdef DEBUG_SG
  eprintf("\t+ (%s) Completed initialization of new sg_ctx!\n", __FUNCTION__);
#endif
}

/* 1 on error, 0 on success */
int put_u64_sg(sg_ctx_t *ctx, uint64_t key, const void *value, size_t len) {
  char key_buf[22];
  int ret;
  if (iota_u64(key, key_buf, 22) == NULL)
    return 1;
  ret = put_db(&ctx->db, key_buf, value, len);
  return ret;
}

int get_u64_sg(sg_ctx_t *ctx, uint64_t key, void **value, size_t *len) {
  char key_buf[22];
  int ret;
  if (iota_u64(key, key_buf, 22) == NULL)
    return 1;
  ret = get_db(&ctx->db, key_buf, value, len);
  return ret;
}

/* 1 on error, 0 on success */
int put_sg(sg_ctx_t *ctx, const char *key, const void *value, size_t len) {
  return put_db(&ctx->db, key, value, len);
}

int get_sg(sg_ctx_t *ctx, const char *key, void **value, size_t *len) {
  int ret = get_db(&ctx->db, key, value, len);
#ifdef DEBUG_SG
  if (ret) {
    eprintf("\t+ (%s) Failed to entry with key %lu!\n", __FUNCTION__, key);
  } else {
    eprintf("\t+ (%s) Successfully entry with key %lu!\n", __FUNCTION__, key);
  }
#endif
  return ret;
}

int find_sg(sg_ctx_t *ctx, uint64_t key, void *value, size_t len) {
  int ret = 0;
//	int ret = get_u64_db(&ctx->db, key, value, len);
#ifdef DEBUG_SG
  if (!ret) {
    eprintf("\t+ Failed to find key %lu!\n", key);
  } else {
    eprintf("\t+ Successfully found key %lu!\n", key);
  }
#endif
  return ret;
}

int remove_sg(sg_ctx_t *ctx, uint64_t key) { return 0; }

int count_sg(sg_ctx_t *ctx) { return 0; }

int save_sg(sg_ctx_t *ctx, const char *filename) {
  int ret = save_db(&ctx->db);
  return ret;
}

int load_sg(sg_ctx_t *ctx, const char *filename) {
  int ret = load_db(&ctx->db);
  return ret;
}

void print_sg(sg_ctx_t *ctx, void (*format)(const void *data)) {
  db_print(&ctx->db, format);
}

static int serialize_and_seal_sg(sg_ctx_t *ctx) {
  // eprintf("+ (%s - %d)\n", __FUNCTION__, __LINE__);
  StateSg state = STATE_SG__INIT;
  state.kc = malloc(sizeof(Keycert));
  state.t = malloc(sizeof(Table));
  keycert__init(state.kc);
  table__init(state.t);
  protobuf_pack_keycert(&ctx->kc, state.kc);
  protobuf_pack_store(&ctx->db.table, state.t);

  size_t len = state_sg__get_packed_size(&state);
  uint8_t *buf = malloc(len);
  state_sg__pack(&state, buf);
  int ret = seal(ctx->db.db_filename, buf, len);

  protobuf_free_packed_keycert(state.kc);
  protobuf_free_packed_store(state.t);
  free(state.kc);
  free(state.t);
  free(buf);

  return ret;
}

static int unseal_and_deserialize_sg(sg_ctx_t *ctx) {
  // eprintf("+ (%s - %d)\n", __FUNCTION__, __LINE__);
  size_t len = 0;
  uint8_t *buf = NULL;
  int ret = unseal(ctx->db.db_filename, &buf, &len);
  if (ret) {
    return ret;
  }

  StateSg *state = NULL;
  state = state_sg__unpack(NULL, len, buf);
  if (!state) {
    return 1;
  }

  protobuf_unpack_store(&ctx->db.table, state->t);
  protobuf_unpack_keycert(&ctx->kc, state->kc);

  table__free_unpacked(state->t, NULL);
  // keycert__free_unpacked(state->kc, NULL);
  // state_sg__free_unpacked(state, NULL);

  return 0;
}

