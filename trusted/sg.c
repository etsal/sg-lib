#include "keycert.pb-c.h"
#include "librassl/attester.h"
#include "sg.h"
#include "sg.pb-c.h"
#include "sg_common.h"
#include "sg_util.h"
#include "store.pb-c.h"
#include "wolfssl_enclave.h"
#include "sg_t.h" // ocalls
extern ra_tls_options_t global_opts;

//#define DEBUG_SG 1

// initConfig
// initACL
// loadConfig
// loadACL
// initServer
static int dump_sg(sg_ctx_t *ctx);
static int undump_sg(sg_ctx_t *ctx);

void
init_sg(sg_ctx_t *ctx, const char *configfilename)
{
	config_ctx_t conf;

	// Load filenames from config file
	ocall_load_config(NULL, configfilename, &conf);

	// Load filenames to sg_ctx
	memcpy(ctx->statefilename, conf.statefilename,
	    strlen(conf.statefilename) + 1);
	
    memcpy(ctx->policyfilename, conf.policyfilename,
	    strlen(conf.policyfilename) + 1);

    // Load state
    int ret = undump_sg(ctx);
    if (ret) {
        init_new_sg(ctx); 
    }

    // Load policy
    // TODO: read and load from a policy file
        
}

void
init_new_sg(sg_ctx_t *ctx)
{
	ctx->kc.der_key_len = DER_KEY_LEN;
	ctx->kc.der_cert_len = DER_CERT_LEN;

#ifdef DEBUG_SG
	eprintf("\t+ Creating RA-TLS Attestation Keys and Certificate\n");
#endif
	create_key_and_x509(ctx->kc.der_key, &ctx->kc.der_key_len,
	    ctx->kc.der_cert, &ctx->kc.der_cert_len, &global_opts);

#ifdef DEBUG_SG
//    eprintf("+ Turning on wolfssl debugging\n");
//    enc_wolfSSL_Debugging_ON();
#endif

#ifdef DEBUG_SG
	eprintf("\t+ Initializing RA-TLS Server ...\n");
#endif
	init_ratls_server(&ctx->ratls, &ctx->kc);

#ifdef DEBUG_SG
	eprintf("\t+ Initializing Key Value Store ...\n");
#endif
	init_db(&ctx->db, NULL, NULL, NULL);

#ifdef DEBUG_SG
	eprintf("\t+ Completed initialization of new sgx_ctx!\n");
#endif
}

void start_server_sg(sg_ctx_t *ctx)
{
    init_ratls_server(&ctx->ratls, &ctx->kc);
}

int
add_sg(sg_ctx_t *ctx, uint64_t key, const void *value, size_t len)
{
	int ret = put_u64_db(&ctx->db, key, value, len);
#ifdef DEBUG_SG
	if (!ret) {
		eprintf("\t+ Successfully added key %lu!\n", key);
	} else {
		eprintf("\t+ Failed to add key %lu!\n", key);
	}
#endif
	return ret;
}

int
find_sg(sg_ctx_t *ctx, uint64_t key, void *value, size_t len)
{
	int ret = get_u64_db(&ctx->db, key, value, len);
#ifdef DEBUG_SG
	if (!ret) {
		eprintf("\t+ Failed to find key %lu!\n", key);
	} else {
		eprintf("\t+ Successfully found key %lu!\n", key);
	}
#endif
	return ret;
}

int
remove_sg(sg_ctx_t *ctx, uint64_t key)
{
	return 0;
}

int
count_sg(sg_ctx_t *ctx)
{
	return 0;
}

int
save_sg(sg_ctx_t *ctx, const char *filename)
{
	int ret = db_save(&ctx->db, filename);
	return ret;
}

int
load_sg(sg_ctx_t *ctx, const char *filename)
{
	int ret = db_load(&ctx->db, filename);
	return ret;
}

int
listen_updates_sg(sg_ctx_t *ctx)
{
//    eprintf("\t+ %s : start\n", __FUNCTION__);
#ifdef DEBUG_SG
	eprintf("\t+ Listening for client connections ...\n", __FUNCTION__);
#endif
	int ret = listen_ratls_server(&ctx->ratls);
	if (ret) {
		eprintf("\t+ %s : Error, listen_ratls_server returned %d\n",
		    __FUNCTION__, ret);
		return ret;
	}

	uint32_t update_len = 16348;
	uint8_t *update = malloc(update_len);

#ifdef DEBUG_SG
	eprintf("\t+ RA-TLS Connection successful, reading update ...\n",
	    __FUNCTION__);
#endif
	ret = read_ratls(&ctx->ratls, update, update_len);
	if (ret < 0) {
		eprintf("\t+ %s : Error, read_ratls returned %d\n",
		    __FUNCTION__, ret);
	}

#ifdef DEBUG_SG
	eprintf("\t+ Recieved update of len %d\nTODO: Merge update\n",
	    __FUNCTION__, ret);
	edividerWithText("Recieved Update");
	eprintf("len %d\n%s\n", ret, hexstring(update, ret));
	edivider();
#endif

	free(update);
	close_ratls_server(&ctx->ratls);

	return 0;
}

/*
 * Returns 0 on success, 1 on error
 */
int
send_update_sg(sg_ctx_t *ctx, const char *host)
{
#ifdef DEBUG_SG
	eprintf("\t+ Initializing RA-TLS Client ...\n", __FUNCTION__);
#endif
	ratls_ctx_t cli_ctx;
	int ret = init_ratls_client(&cli_ctx, &ctx->kc, host);
	if (ret) {
		eprintf(
		    "\t+ %s : Failed to connect to %s\n", __FUNCTION__, host);
		return 1;
	}

	uint8_t *update;
	size_t update_len = 0;

#ifdef DEBUG_SG
	eprintf("\t+ Preparing update\n", __FUNCTION__);
#endif
	db_get_update_len(&ctx->db, &update_len);
	if (!update_len) {
		eprintf("\t+ %s : Update is of length %d\n", __FUNCTION__,
		    update_len);
		return 1;
	}

	update = malloc(update_len);
	db_get_update(&ctx->db, update, update_len);

#ifdef DEBUG_SG
	edividerWithText("Prepared Update");
	eprintf("len %d\n%s\n", update_len, hexstring(update, update_len));
	edivider();
	eprintf("\t+ Sending update\n", __FUNCTION__);
#endif

	ret = write_ratls(&cli_ctx, update, update_len);

#ifdef DEBUG_SG
	eprintf("\t+ Finished sending update\n", __FUNCTION__);
#endif

	destroy_ratls(&cli_ctx);
	if (ret != update_len) {
		return 1;
	}
	return 0;
}

void
print_sg(sg_ctx_t *ctx, void (*format)(const void *data))
{
	db_print(&ctx->db, format);
}

static int
dump_sg(sg_ctx_t *ctx)
{
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
	int ret = seal(ctx->statefilename, buf, len);

	protobuf_free_packed_keycert(state.kc);
	protobuf_free_packed_store(state.t);
	free(state.kc);
	free(state.t);
	free(buf);

	return ret;
}

static int
undump_sg(sg_ctx_t *ctx)
{
	size_t len = 0;
	uint8_t *buf = NULL;
	int ret = unseal(ctx->statefilename, &buf, &len);
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
