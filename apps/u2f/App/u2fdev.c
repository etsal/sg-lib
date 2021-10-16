#include <sys/types.h> // ?
#include <sys/queue.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h> 

#include "sgx_eid.h"    /* sgx_enclave_id_t */
#include "sgx_error.h"  /* sgx_status_t */

#include "u2fdev.h"
#include "Enclave_u.h"
#include "common.h"
#include "BearSSL/inc/bearssl.h"
#include "u2f.h"
#include "u2f_hid.h"
#include "u2f_utils.h"
#include "sg_common.h"

//#define DEBUG 				1
//#define DEBUG_DEV 			1
#define SECP256_PUB_SIZE 	65 // TODO put this somewhere

#define LO_BYTE(x) 			(x & 0xff)
#define HI_BYTE(x) 			((x & 0xff00) >> 8)

typedef struct prepared_frame {
	U2FHID_FRAME frame;
	TAILQ_ENTRY(prepared_frame) entries;
} U2FHID_CONT_FRAME;

typedef struct {
	pthread_mutex_t m;
	TAILQ_HEAD(, prepared_frame) head;
} FRAME_QUEUE;

FRAME_QUEUE fq;	// Must be initialized

#define FRAME_QUEUE_LOCK() pthread_mutex_lock(&fq.m)
#define FRAME_QUEUE_UNLOCK() pthread_mutex_unlock(&fq.m)

typedef enum {
	READ_INIT,
	READ_VER,
	READ_REG,
	READ_AUTH,
	READ_CONT,
	UNKNOWN
} U2F_STATE;

typedef struct u2f_context {
	uint32_t cid;
	int read_state;
	char nonce[8];
	char reg_request[sizeof(U2F_REGISTER_REQ)];
	int reg_req_so_far;
	uint8_t control_byte;
	char auth_request[sizeof(U2F_AUTHENTICATE_REQ)];
	int auth_req_so_far;
	int auth_counter;
} U2F_CTX;

U2F_CTX *cur_ctx;
extern sgx_enclave_id_t global_eid;

static size_t prepare_frames(uint8_t *msg, size_t msg_len, U2FHID_FRAME *frame, uint32_t cid, uint8_t cmd, uint16_t status);
static void process_u2fhid_msg_cmd(U2F_CTX *ctx, U2FHID_FRAME *frame);
static void process_init_packet(U2F_CTX *ctx, U2FHID_FRAME *frame);
static void process_cont_packet(U2F_CTX *ctx, U2FHID_FRAME *frame);

static void generate_init_resp(U2F_CTX *ctx, U2FHID_FRAME *frame);
static void generate_ver_resp(U2F_CTX *ctx, U2FHID_FRAME *frame);
static void generate_reg_resp(U2F_CTX *ctx, U2FHID_FRAME *frame); // TODO
static void generate_auth_resp(U2F_CTX *ctx, U2FHID_FRAME *frame); // TODO

static void 
print_bytes(uint8_t *data, size_t len) 
{
    for (int i=0; i<len; ++i) {printf("%02x", data[i]);}
    printf("\n");
}

static void 
print_response_state(int state)
{
	switch (state) {
		case READ_INIT:
			printf("U2F_INIT Response\n");
			break;
		case READ_VER:
			printf("U2F_VERSION Response\n");
			break;
		case READ_REG:
			printf("U2F_REGISTER Response\n");
			break;
		case READ_AUTH:
			printf("U2F_AUTHENTICATE Response\n");
			break;
		case READ_CONT: 
			printf("U2F_CONT Response\n");
			break;
		default:
			printf("UNKNOWN Response\n");
	}
}

void init_u2fdev(int uid) {
	TAILQ_INIT(&fq.head);
	int ret = pthread_mutex_init(&fq.m, NULL);
	assert(ret == 0);
	cur_ctx = NULL;

	sgx_status_t status = ecall_init_device(global_eid, uid);
	if (status != SGX_SUCCESS) {
		exit(1); //TODO
	}
}

void destroy_u2fdev() {
	U2FHID_CONT_FRAME *f1, *f2;
	FRAME_QUEUE_LOCK();
	f1 = TAILQ_FIRST(&fq.head);
     while (f1 != NULL) {
             f2 = TAILQ_NEXT(f1, entries);
             free(f1);
             f1 = f2;
     }
	FRAME_QUEUE_UNLOCK();
	pthread_mutex_destroy(&fq.m);
}

void* listen_updates_u2fdev()
{
	sgx_status_t status = SGX_SUCCESS;
	int ret = 0;

	while(status == SGX_SUCCESS && ret == 0) {
		status = ecall_listen_updates(global_eid, &ret);
	}
}

int
open_(struct cuse_dev *dev, int fflags)
{
#ifdef DEBUG_DEV
	printf("%s called\n", __FUNCTION__);
#endif
	return 0;
}

int
close_(struct cuse_dev *dev, int fflags)
{
#ifdef DEBUG_DEV
	printf("%s called\n", __FUNCTION__);
#endif
	return 0;
}

int
poll_(struct cuse_dev *dev, int fflags, int events)
{
#ifdef DEBUG_DEV
	printf("%s called\n", __FUNCTION__);
#endif
	return 0;

}

/*
 * Read is called as many times as re
 */ 
int
read_(struct cuse_dev *dev, int fflags, void *user_ptr, int len)
{
	void *msg;
	U2FHID_FRAME frame;
	memset(&frame, 0, sizeof(U2FHID_FRAME));

#ifdef DEBUG_DEV
	printf("\n\n\n%s called\n", __FUNCTION__);
#endif

	U2F_CTX *ctx = cur_ctx;
	int state = ctx->read_state;
	ctx->read_state = -1;	// Set the next read state to error
#ifdef DEBUG_DEV
	print_response_state(state);
#endif
	switch (state) {
		case READ_INIT:
			generate_init_resp(ctx, &frame);
			msg = &frame;
			break;
		case READ_VER:
			generate_ver_resp(ctx, &frame);
			msg = &frame;
			break;
		case READ_REG:
			generate_reg_resp(ctx, &frame);
			msg = &frame;
			break;
		case READ_AUTH:
			generate_auth_resp(ctx, &frame);
			msg = &frame;
			break;
		case READ_CONT: 
			FRAME_QUEUE_LOCK();
			U2FHID_CONT_FRAME *cur = TAILQ_FIRST(&fq.head);
			if (!cur) {
				printf("Error, expecting to send continuation frame but 0 found!\n");
				exit(1); //TODO: error handling
			}
			U2FHID_CONT_FRAME *next = TAILQ_NEXT(cur, entries);
			if (next) {
				ctx->read_state = READ_CONT; // More frames to send
			}
			/* Copy to local var so we can delete the frame from queue */
			memcpy(&frame, &cur->frame, sizeof(U2FHID_FRAME));

			/* Delete cur from queue */
			TAILQ_REMOVE(&fq.head, cur, entries);
			free(cur);

			msg = &frame;
			FRAME_QUEUE_UNLOCK();
			break;
		default:
			printf("%s : Error, Read state %d is not supported\n", __FUNCTION__, state);
			exit(1);
			break;
	}

#ifdef DEBUG_DEV
	//print_frame(&frame);
	//printf("Sending frame ...\n");
#endif

	// Send frame
	int ret = cuse_copy_out(msg, user_ptr, sizeof(U2FHID_FRAME));
	if (ret) {
		printf("Error, cuse_copy_out failed with %d.\n", ret);
		exit(1); //TODO
	}

	return sizeof(U2FHID_FRAME);
}

static void
generate_init_resp(U2F_CTX *ctx, U2FHID_FRAME *frame)
{
	U2FHID_INIT_RESP response;
	memset(&response, 0, sizeof(U2FHID_INIT_RESP));
	response.cid = ctx->cid;
	memcpy(response.nonce, ctx->nonce, INIT_NONCE_SIZE);	// Set nonce
	int ret = prepare_frames((uint8_t *)&response, sizeof(U2FHID_INIT_RESP), frame, CID_BROADCAST, U2FHID_INIT, 0);
	if (ret > 0) {
		// TODO
		exit(1);
	}
}

static void
generate_ver_resp(U2F_CTX *ctx, U2FHID_FRAME *frame)
{
	U2F_VERSION_RESP response;
	memset(&response, 0, sizeof(U2F_VERSION_RESP));
	assert(U2F_PROTOCOL_VERSION == 2);
	//uint8_t *buf = response->version;
	response.version[0] = 'U';
	response.version[1] = '2';
	response.version[2] = 'F';
	response.version[3] = '_';
	response.version[4] = 'V';
	response.version[5] = '2';
	int ret = prepare_frames((uint8_t *)&response, sizeof(U2F_VERSION_RESP), frame, ctx->cid, U2FHID_MSG, U2F_SW_NO_ERROR);
	if (ret > 0) {
		// Error handle
	}
}


static void
generate_reg_resp(U2F_CTX *ctx, U2FHID_FRAME *frame)
{
	//uint8_t *response = NULL;
	//size_t response_len = 0;
	U2F_REGISTER_REQ *request = (U2F_REGISTER_REQ *) ctx->reg_request;

#ifdef DEBUG
	printf("+ REGISTERING new site \n");
#endif


	/* Generate User public & private key, and key handle 
     * - The key handle is a hash of the private key
     *   we only that the first 8 bytes and set it to a uint64_t
	 */
	unsigned char key_handle[br_sha256_SIZE] = {0};
	uint8_t key_handle_len = br_sha256_SIZE;
	unsigned char public_key[SECP256_PUB_SIZE+1];
	sgx_status_t status = ecall_generate_site_keys(global_eid, key_handle, key_handle_len, public_key, SECP256_PUB_SIZE);
	if (status != SGX_SUCCESS) {
		printf("+ SGX error\n");
		exit(1);
	}
#ifdef DEBUG_DEV
	printf("+ Site keys generated, generating signature \n");
#endif

	/* Assemble signature base 
	 * - Reserved bytes
	 * - App parameter
	 * - Challenge parameter
	 * - Key handle
	 * - User public key
	 */
	size_t sig_base_len = 1 + 32 + 32 + key_handle_len + 65;
	unsigned char sig_base[sig_base_len];
	int offset = 0;

	sig_base[offset++] = 0x00;

	memcpy(sig_base + offset, request->appId, U2F_APPID_SIZE);
	offset += U2F_APPID_SIZE;

	memcpy(sig_base + offset, request->chal, U2F_CHAL_SIZE);
	offset += U2F_CHAL_SIZE;

	memcpy(sig_base + offset, key_handle, key_handle_len);
	offset += key_handle_len;

	memcpy(sig_base + offset, public_key, SECP256_PUB_SIZE);
	offset += SECP256_PUB_SIZE;

	assert(offset == sig_base_len);

#ifdef DEBUG_DEV
	/*
	printf("Byte String Size \t\t%d = \n", sig_base_len);
	printf("+ Application Parameter \t%d\n", U2F_APPID_SIZE);
	printf("+ Challenge Parameter \t\t%d\n", U2F_CHAL_SIZE);
	printf("+ Key Handle \t\t\t%d\n", key_handle_len);
	printf("+ User Public Key \t\t%d\n", SECP256_PUB_SIZE);
	printf("+ Other \t\t\t%d\n", 1);
	printf("Byte String (%d bytes): \n", sig_base_len);
	print_bytes(sig_base, sig_base_len);
	printf("\n\n");
	*/
#endif

	/* Sign signature base to produce the signature.
	 * - Signing with the device private attestation key
	 * - Sign the SHA256 hash of the byte string
	 * - The signature is in ASN1 format
	 */
	unsigned char signature[ASN1_P256_SIGNATURE_SZ+1];
	int signature_len = 0;
	status = ecall_generate_registration_signature(global_eid, &signature_len, 
		key_handle, key_handle_len, 
		sig_base, sig_base_len, 
		signature, ASN1_P256_SIGNATURE_SZ);
	if (status != SGX_SUCCESS) {
		printf("SGX error\n");
		exit(1);
	}
	if (!signature_len || signature_len > ASN1_P256_SIGNATURE_SZ) {
		printf("%s : Error, signature len is %d\n", __FUNCTION__, signature_len);
		exit(1);
	}

	/* Get the device attestation key certificate
	 * - Need this to build the registration response
	 */
	unsigned char cert[CERT_MAX_LEN] ={0};
	int cert_len = 0;
	status = ecall_get_cert(global_eid, &cert_len, cert, CERT_MAX_LEN);
	if (status != SGX_SUCCESS) {
		printf("%s : ecall_get_cert() SGX error\n", __FUNCTION__);
		exit(1); //TODO
	}
	if (!cert_len && cert_len <= CERT_MAX_LEN) {
		printf("%s : Error, cert len is %d\n", __FUNCTION__, cert_len);
		exit(1); //TODO
	}

	/* Assemble registration response
	 * - Reserved byte
	 * - User public key
	 * - Length of key handle
	 * - Key handle
	 * - X509 Cert - self-signed (device attestation pkey is the subject & CA)
	 * - Signature - signed with device attestation skey
	 */
	size_t response_len = 1 + SECP256_PUB_SIZE + 1 + key_handle_len + cert_len + signature_len;
	unsigned char *response = malloc(response_len);
	memset(response, 0, response_len);

	offset = 0;
	response[offset++] = 0x05;
	// User public key
	memcpy(response + offset, public_key, SECP256_PUB_SIZE);
	offset += SECP256_PUB_SIZE;
	// Key handle len (max 255)
	memcpy(response + offset, &key_handle_len, 1);
	offset += 1;
	// Key handle
	memcpy(response + offset, key_handle, key_handle_len);
	offset += key_handle_len;
	// Cert
	memcpy(response + offset, cert, cert_len);
	offset += cert_len;
	// Signature
	memcpy(response + offset, signature, signature_len);
	offset += signature_len;

	assert(offset == response_len);

#ifdef DEBUG_DEV
	/*
	printf("Response Msg Size \t\t%d = \n", response_len);
	printf("  User Public Key \t\t%d\n", SECP256_PUB_SIZE);
	printf("+ Key Handle \t\t\t%d\n", key_handle_len);
	printf("+ Attestation Certificate \t%d\n", cert_len);
	printf("+ Signature \t\t\t%d\n", signature_len);
	printf("+ Other \t\t\t%d\n\n", 2);

	edividerWithText("Resistration Response Message");
	print_bytes(response, response_len);
	edivider();
	*/
#endif

	int ret = prepare_frames(response, response_len, frame, ctx->cid, U2FHID_MSG, U2F_SW_NO_ERROR);
	if (ret > 0) {
		assert(ret < MAX_SEQ_NUM);
		ctx->read_state = READ_CONT;
	}
	free(response);
}


static void
generate_auth_resp(U2F_CTX *ctx, U2FHID_FRAME *frame)
{
	U2F_AUTHENTICATE_RESP response;
	size_t response_len = 0;
	U2F_AUTHENTICATE_REQ *request = (U2F_AUTHENTICATE_REQ *)ctx->auth_request;
	uint16_t flag = 0;
	
	uint32_t site_counter = 0;
	uint8_t *key_handle = request->keyHandle; // TODO: weird stuff happens if casting to unsigned char
	size_t key_handle_len = (size_t)request->keyHandleLen;

	sgx_status_t status = ecall_inc_and_get_site_counter(global_eid, &site_counter, key_handle, key_handle_len);

	assert(site_counter);

#ifdef DEBUG
	printf("+ AUTHENTICATING site\n");
#endif


#ifdef DEBUG_DEV
	/*
	printf("Key Handle (%d): ", key_handle_len);
	print_bytes(key_handle, key_handle_len);
	printf("Site Counter : %d\n", site_counter);
	printf("Request App Param :");
	print_bytes(request->appId, U2F_APPID_SIZE);
	printf("Request Chal Param :");
	print_bytes(request->chal, U2F_CHAL_SIZE);
	*/
#endif

	switch(ctx->control_byte) {
		case U2F_AUTH_CHECK_ONLY:
			flag = U2F_SW_CONDITIONS_NOT_SATISFIED;
			response_len = 0;
			break;
		case U2F_AUTH_ENFORCE: {
				flag = U2F_SW_NO_ERROR;

				/* Assemble signature base */
				size_t sig_base_len = U2F_APPID_SIZE + 1 + U2F_CTR_SIZE + U2F_CHAL_SIZE;
				unsigned char sig_base[sig_base_len];
				int offset = 0;
				int ctr_offset = 0;

				memset(sig_base, 0, sig_base_len);

				memcpy(sig_base, request->appId, U2F_APPID_SIZE); // App parameter
				offset += U2F_APPID_SIZE;

				sig_base[offset++] = 1;	// User presence

				ctr_offset = offset;
			 	sig_base[offset++] = (uint8_t)(site_counter >> 24) & 0xFF; //Counter
				sig_base[offset++] = (uint8_t)(site_counter >> 16) & 0xFF;
				sig_base[offset++] = (uint8_t)(site_counter >> 8) & 0xFF;
				sig_base[offset++] = (uint8_t)(site_counter) & 0xFF;

				memcpy(sig_base + offset, request->chal, U2F_CHAL_SIZE); // Challenge parameter
				offset += U2F_CHAL_SIZE;

				assert(offset == sig_base_len);	

#ifdef DEBUG_DEV
				/*
				printf("Authentication Response Signature Base (%d): \n\t", sig_base_len);
				print_bytes(sig_base, U2F_APPID_SIZE);
				print_bytes(sig_base + U2F_APPID_SIZE, 1);
				print_bytes(sig_base + U2F_APPID_SIZE + 1, U2F_CTR_SIZE);
				print_bytes(sig_base, sig_base_len);	
				*/
#endif

				/* Sign signature base */
				unsigned char signature[ASN1_P256_SIGNATURE_SZ+1]; 
				int signature_len = 0;
				status = ecall_generate_authentication_signature(global_eid, &signature_len, 
					key_handle, key_handle_len, 
					sig_base, sig_base_len, 
					signature, ASN1_P256_SIGNATURE_SZ);
				if (status != SGX_SUCCESS) {
					printf("SGX error\n");
				}
				if (!signature_len || signature_len > ASN1_P256_SIGNATURE_SZ) {
					printf("%s : Error, signature len is %d\n", __FUNCTION__, signature_len);
					exit(1);
				}

				/* Assemble authentication response 
				 * - flag
				 * - counter
				 * - signature
				 */
				memset(&response, 0, sizeof(response));
				response.flags = 1;
				response.ctr[0] = sig_base[ctr_offset++];
				response.ctr[1] = sig_base[ctr_offset++];
				response.ctr[2] = sig_base[ctr_offset++];
				response.ctr[3] = sig_base[ctr_offset];
				memcpy(&response.sig, signature, signature_len);
				response_len = 5 + signature_len;
//#ifdef DEBUG_DEV
				edividerWithText("Authentication Response");
				printf("+ Flags          : %d\n", response.flags);
				printf("+ Counter        : %x %x %x %x\n", response.ctr[0], response.ctr[1], response.ctr[2], response.ctr[3]);
				printf("+ Signature (%d) : %s...\n", signature_len, hexstring(signature, 10));
				edivider();

				//printf("Byte String :");
				//print_bytes(signature, signature_len);	
//#endif



			}
			break;
		default:
			printf("%s : Unknown control byte %02x\n", ctx->control_byte);
			exit(1);
			break;
	}

	int ret = prepare_frames((uint8_t *)&response, response_len, frame, ctx->cid, U2FHID_MSG, flag);
	if (ret > 0) {
		assert(ret < MAX_SEQ_NUM);
		ctx->read_state = READ_CONT;
	}
}

int
write_(struct cuse_dev *dev, int fflags, const void *user_ptr, int len)
{
	U2FHID_FRAME frame;
	cuse_copy_in(user_ptr, &frame, len);
	assert(len == sizeof(U2FHID_FRAME));

#ifdef DEBUG_DEV
	printf("\n\n\n%s called\n", __FUNCTION__);
#endif 

	U2F_CTX *ctx = cur_ctx; //get_ctx(&ctx_table. frame.cid); // Do kv search to get the context
	if (!ctx) {
#ifdef DEBUG_DEV
		printf("%s : creating U2F_CTX\n", __FUNCTION__);
#endif
		// No matching context for this channel identifier
		ctx = (U2F_CTX *)malloc(sizeof(U2F_CTX));
		memset(ctx, 0, sizeof(sizeof(U2F_CTX)));
		ctx->cid = 0x04030201; // TODO generate channel ID
	}

#ifdef DEBUG_DEV
	//printf("FRAME TYPE : %s\n", FRAME_TYPE(frame) == TYPE_INIT ? "TYPE_INIT" : "TYPE_CONT");
	//print_frame(&frame);
	//printf("\n");
#endif

	switch (FRAME_TYPE(frame)) {
		case TYPE_INIT:
			process_init_packet(ctx, &frame);
			break;
		case TYPE_CONT:
			process_cont_packet(ctx, &frame);
			break;
		default:
			printf("Error: Frame type 0x%x is not supported.", FRAME_TYPE(frame));
			break;
	}
	// TODO: push ctx onto FIFO global queue
	if (cur_ctx == NULL) {
		cur_ctx = ctx;
	}

	return 64; // WHY?
}

static void
process_init_packet(U2F_CTX *ctx, U2FHID_FRAME *frame)
{
	U2FHID_INIT_REQ *request;
	assert(FRAME_TYPE(*frame) == TYPE_INIT);
	switch(FRAME_CMD(*frame)) {
		case U2FHID_INIT:
			request = (U2FHID_INIT_REQ *)&frame->init.data;
			memcpy(ctx->nonce, request->nonce, INIT_NONCE_SIZE);	// Save nonce
			ctx->read_state = READ_INIT;						// Set the state to READ_INIT
			break;
		case U2FHID_MSG:
			process_u2fhid_msg_cmd(ctx, frame);
			break;
		default:
			printf("Error: U2FHID Command 0x%x is not supported.", FRAME_CMD(*frame));
			// Set faulty read state
			ctx->read_state = -1;
			break;
	}
}

static void
process_cont_packet(U2F_CTX *ctx, U2FHID_FRAME *frame)
{
	assert(FRAME_TYPE(*frame) == TYPE_CONT);
	int payload_len;

	//print_frame(frame);
	switch (ctx->read_state) {
		case READ_REG:
			payload_len = 64 - U2F_REQ_MSG_MAX_DATA_SIZE;
			memcpy(ctx->reg_request + ctx->reg_req_so_far,
			    (char *)frame->cont.data, payload_len);
			ctx->reg_req_so_far += payload_len;
			break;
		case READ_AUTH:
			payload_len = 64 - 5;
			memcpy(ctx->auth_request + ctx->auth_req_so_far,
			    (char *)frame->cont.data, payload_len);
			ctx->auth_req_so_far += payload_len;
			break;
		default:
			printf("Error: Cannot proccess continuation packet\n");
			exit(1);
			break;
	}
}

static void 
process_u2fhid_msg_cmd(U2F_CTX *ctx, U2FHID_FRAME *frame)
{
	assert(FRAME_CMD(*frame) == U2FHID_MSG);
	U2F_REQ_MSG *msg = (U2F_REQ_MSG *)&frame->init.data;
	uint8_t type = msg->ins;

#ifdef DEBUG_DEV
	printf("%s Request\n", get_U2F_cmd_str(type));
#endif

	switch(type) {
		case U2F_VERSION:
			ctx->read_state = READ_VER;		// Set the state to READ_VERSION
			break;
		case U2F_REGISTER:
			// Copy message data (msg->data) to registration_request buffer (64 bytes = U2F_REQ_MSG_MAX_DATA_SIZE)
			memcpy(ctx->reg_request, (char *)msg->data, U2F_REQ_MSG_MAX_DATA_SIZE);
			ctx->reg_req_so_far = U2F_REQ_MSG_MAX_DATA_SIZE;
			ctx->read_state = READ_REG;		// Set read state to READ_REGISTRATION
			break;
		case U2F_AUTHENTICATE:
			// Copy message data (msg->data) to authentication_request buffer (64 bytes = U2F_REQ_MSG_MAX_DATA_SIZE)
			memcpy(ctx->auth_request, (char *)msg->data, U2F_REQ_MSG_MAX_DATA_SIZE);
			ctx->auth_req_so_far = U2F_REQ_MSG_MAX_DATA_SIZE;
			ctx->control_byte = msg->p1;	// Save the control byte (msg->p1)
			ctx->read_state = READ_AUTH;	// Set read state to READ_AUTHENTICATION
			break;
		default: 
			printf("Error, U2F Message 0x%x is not supported.", type);
			ctx->read_state = -1;	// Set faulty read state
			break;
	}
}

/* Create an init frame and 0 or more continuation frames
 * that are pushed to a global queue.
 *
 * @param msg Message to be transmitted.
 * @param msg_len
 * @param init_frame Init frame to be filled by this function.
 * @param status ADPU status code to append to message.
 * @return Number of continuation packets.
 *
 * Input parameter msg is packet-ized, init_frame is initialized to the first
 * frame and any continuation frames will be pushed to global queue, with the
 * number of cont frames pushed returned. todo pass head
 */
static size_t
prepare_frames(uint8_t *msg, size_t msg_len, U2FHID_FRAME *frame,
    uint32_t cid, uint8_t cmd, uint16_t status)
{
	uint8_t *adpu = NULL;
	size_t adpu_len = 0, seq = 0;
	int so_far = 0;

	/* Create an ADPU response (that is just msg + 2 bytes) */
	adpu = malloc(msg_len + 2);
	adpu_len = msg_len + 2;
	memcpy(adpu, msg, msg_len);

	/* Do not set status bytes (U2F_INIT & U2F_VERSION) */
	if (status == 0) {
		adpu_len = msg_len;
	} else {
		adpu[msg_len] = HI_BYTE(status);
		adpu[msg_len + 1] = LO_BYTE(status);
	}

	frame->cid = cid;
	frame->init.cmd = cmd;
	frame->init.bcnth = HI_BYTE(adpu_len);
	frame->init.bcntl = LO_BYTE(adpu_len);
	memcpy(frame->init.data, adpu, INIT_PAYLOAD_SIZE);

#ifdef DEBUG_DEV
	//printf("Prepared frame ....\n");
	//print_frame(frame);
#endif

	FRAME_QUEUE_LOCK();
	/* Queue MUST be empty when we prepare new frames */
	if (!TAILQ_EMPTY(&fq.head)) {
		printf("Error, %s : global queue not empty!\n", __FUNCTION__);
		exit(1);
		// TODO: maybe retry as another thread may be currently sending frames
		seq = SIZE_MAX;
		goto cleanup;

	}

	/* Push continuation packets into the queue to be sent */
	so_far = INIT_PAYLOAD_SIZE;
	while (so_far < adpu_len) {
		int send = (adpu_len - so_far) > CONT_PAYLOAD_SIZE ? CONT_PAYLOAD_SIZE : (adpu_len - so_far);
		U2FHID_CONT_FRAME *cont_frame = (U2FHID_CONT_FRAME *)malloc(sizeof(U2FHID_CONT_FRAME));
		memset(cont_frame, 0, sizeof(U2FHID_CONT_FRAME));
		cont_frame->frame.cid = cid;
		cont_frame->frame.cont.seq = seq++;
		memcpy(&(cont_frame->frame.cont.data), adpu + so_far, send);
#ifdef DEBUG_DEV
		//printf("Prepared frame ....\n");
		//print_frame(&cont_frame->frame);
#endif
		/* Push onto queue */
		TAILQ_INSERT_TAIL(&fq.head, cont_frame, entries);
		so_far += send;
	}

cleanup:
	FRAME_QUEUE_UNLOCK();
	free(adpu);
	return seq;
}

