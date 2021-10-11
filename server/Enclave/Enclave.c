#include <sgx_trts.h> // sgx_read_rand
#include <string.h>

#include "Enclave_t.h"
#include "policy.h"
#include "policy_errlist.h"
#include "sg.h"
#include "sg_common.h"
#include "sg_stdfunc.h" // atoi()
#include "sgd_message.h"

sg_ctx_t sg_ctx;
uint32_t last_nonce = 0;
login_t saved_login; // This is really sketchy...

void ecall_test() {}

void ecall_shutdown_sg() {
  cleanup_connections_sg();
  int ret = save_sg(&sg_ctx, NULL);
  //  if (ret)
  //    eprintf("\t+ (%s) Failed to save sg\n", __FUNCTION__);
}

static int get_user_uid(char *username) {
  login_t *login;
  int ret = get_user_by_name(&sg_ctx, username, &login);

  if (!ret) {
    ret = login->uid;
  } else {
    ret = 0;
  }

  free(login);
  return ret;
}

/****************DEBUG**************/
static const char *request_type_str[] = {
    "PUT_REQUEST",   "GET_REQUEST",    "SAVE_REQUEST",
    "PRINT_REQUEST", "GET_USER_BY_ID", "GET_USER_BY_NAME",
    "AUTH_USER",     "BIND_USER",      "PUT_USER"};

static const char *get_cmd_str(int cmd) { return request_type_str[cmd]; }
/**********************************/

void ecall_process_request(uint8_t *data, size_t data_len,
                           struct response_msg *resp) {
  struct request_msg *msg = (struct request_msg *)data;
  void *value = NULL;
  size_t value_len = 0;
  int ret, tmp = 0, clear_login = 1;
  const char *filepath;
  login_t login;

  eprintf("+ (%s) Processing request ... %s\n", __FUNCTION__,
          get_cmd_str(msg->cmd));
  // resp->value_len_max = MAX_VALUE_LEN;

  switch (msg->cmd) {

  case PUT_USER:
    // Assert previous action was BIND_USER
    // Make sure supplied nonce matches the one that is given so that we can
    // ensure it is the same operation
    if (last_nonce != msg->nonce) {
      resp->ret = 1;
      break;
    }
    memcpy(login.user, msg->key, strlen(msg->key) + 1);
    login.uid = ++sg_ctx.next_uid;

    eprintf("+ (%s) Request PUT_USER : new user's uid == %d\n", __FUNCTION__,
            login.uid);

    memcpy(login.password, msg->value, msg->value_len);
    ret = put_user(&sg_ctx, &saved_login, &login);
    resp->ret = ret;
    last_nonce = 0;
    if (ret) {
      eprintf("+ (%s) Request PUT_USER : FAIL \n", __FUNCTION__);
    } else {
      eprintf("+ (%s) Request PUT_USER : SUCCESS \n", __FUNCTION__);
    }
    break;

  case BIND_USER:
    // Bind user
    // Create random nonce to send
    memcpy(login.user, msg->key, strlen(msg->key) + 1);
    login.uid = get_user_uid(msg->key);
    memcpy(login.password, msg->value, msg->value_len);
    ret = auth_user(&sg_ctx, &login);
    resp->ret = ret;
    resp->nonce = 0;
    resp->value_len = 0;
    if (ret) {
      eprintf("+ (%s) Request BIND_USER : Incorrect login\n", __FUNCTION__);
    } else {
      eprintf("+ (%s) Request BIND_USER : Correct login\n", __FUNCTION__);
      sgx_read_rand((unsigned char *)&resp->nonce, sizeof(uint32_t));
      last_nonce = resp->nonce;
      memcpy(&saved_login, &login, sizeof(login_t));
      clear_login = 0;
    }
    break;

  case AUTH_USER:
    memcpy(login.user, msg->key, strlen(msg->key) + 1);
    login.uid = get_user_uid(msg->key);
    memcpy(login.password, msg->value, msg->value_len);
    ret = auth_user(&sg_ctx, &login);
    resp->ret = ret;
    resp->value_len = 0;
    if (ret) {
      eprintf("+ (%s) Request AUTH_USER : Incorrect login\n", __FUNCTION__);
    } else {
      eprintf("+ (%s) Request AUTH_USER : Correct login\n", __FUNCTION__);
    }
    break;

  case GET_USER_BY_NAME:
    ret = get_user_by_name(&sg_ctx, msg->key, (login_t **)&value);
    resp->ret = ret;
    resp->value_len = 0;

    if (ret != ACTION_SUCCESS) {
      break;    
    }

    if (sizeof(login_t) < resp->value_len_max) {
      memcpy(resp->value, (login_t *)value, sizeof(login_t));
      resp->value_len = sizeof(login_t);
    } else {
      eprintf("+ (%s) Error sizeof(login_t) %d >= resp->value_len_max %d\n",
              __FUNCTION__, sizeof(login_t), resp->value_len_max);
      resp->value_len = 0;
    }
    free(value);
    break;

  case GET_USER_BY_ID:
    tmp = atoi(msg->key);
    ret = get_user_by_id(&sg_ctx, tmp, (login_t **)&value);
    resp->ret = ret;
    resp->value_len = 0;

    if (ret != ACTION_SUCCESS) {
      break;    
    }

    if (sizeof(login_t) < resp->value_len_max) {
      memcpy(resp->value, (login_t *)value, sizeof(login_t));
      resp->value_len = sizeof(login_t);
    } else {
      resp->value_len = 0;
    }
    break;
  
  case PUT_REQUEST:
    assert(msg->value_len < MAX_VALUE_LEN);
    ret = put_sg(&sg_ctx, msg->key, msg->value, msg->value_len);
    resp->ret = ret;
    break;
  case GET_REQUEST:
    ret = get_sg(&sg_ctx, msg->key, &value, &value_len);
    resp->ret = ret;
    resp->value_len = value_len;
    if (value_len <
        resp->value_len_max) { // Only copy value if buffer has enough space
      memcpy(resp->value, value, value_len);
    }
    break;
  case SAVE_REQUEST:
    if (msg->filepath[0] == '\0') { // Save to file written in config
      filepath = NULL;
    } else { // Save to specified file
      filepath = msg->filepath;
    }
    ret = save_sg(&sg_ctx, filepath);
    resp->ret = ret;
    break;
  }

  eprintf("+ (%s) Action completed\n", __FUNCTION__);
  eprintf("+ (%s) Printing kvs ...\n", __FUNCTION__);
  eprintf("--------------------------------------------\n");
  print_sg(&sg_ctx, NULL);
  eprintf("--------------------------------------------\n");

  if (clear_login)
    memset(&login, 0, sizeof(login_t));
  if (msg->cmd == PUT_USER && resp->ret == 0) {

    eprintf("+ (%s) Attempting to push update ...\n", __FUNCTION__);
    push_updates_sg(&sg_ctx);
    eprintf("+ (%s) Complete!\n", __FUNCTION__);
  }
}
/* Should return a response_msg rather than ret
 *
int ecall_process_request(uint8_t *data, size_t data_len) {
  struct request_msg *msg = (struct request_msg *)data;
  int ret;
  switch(msg->cmd) {
    case PUT_REQUEST:
      assert(msg->value_len < MAX_VALUE_LEN);
      ret = put_sg(&sg_ctx, msg->key, msg->value, msg->value_len);
    break;
    case GET_REQUEST:
      ret = get_sg(&sg_ctx, msg->key, msg->value, &msg->value_len);
    break;
  }
  return ret;
}
*/

/*
void init() {
  init_sg(&sg_ctx);
}
*/
void connect_cluster() { initiate_connections_sg(&sg_ctx); }

void recieve_cluster_connections() { recieve_connections_sg(&sg_ctx); }

void poll_and_process_updates() { poll_and_process_updates_sg(&sg_ctx); }

int verify_cluster_connections() {
  int ret = 0;
  ret = verify_connections_sg(&sg_ctx);
  return ret;
}

void send_message(const char *msg) { send_msg_sg(&sg_ctx, msg); }

