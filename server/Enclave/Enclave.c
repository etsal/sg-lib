#include <string.h>

#include "Enclave_t.h"
#include "policy.h"
#include "sg.h"
#include "sg_common.h"
#include "sg_stdfunc.h" // atoi()
#include "sgd_message.h"

sg_ctx_t sg_ctx;

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

void ecall_process_request(uint8_t *data, size_t data_len,
                           struct response_msg *resp) {
  struct request_msg *msg = (struct request_msg *)data;
  void *value = NULL;
  size_t value_len = 0;
  int tmp = 0;
  const char *filepath;
  int ret;
  login_t login;
  
  eprintf("+ (%s) start\n", __FUNCTION__);

  //resp->value_len_max = MAX_VALUE_LEN;

  switch (msg->cmd) {
  case AUTH_USER:
    memcpy(login.user, msg->key, strlen(msg->key)+1);
    login.uid = get_user_uid(msg->key);
    memcpy(login.password, msg->value, msg->value_len);
    ret = auth_user(&sg_ctx, &login);
    resp->ret;
    resp->value_len = 0;
    if (ret) {  
      eprintf("+ (%s) Incorrect login\n", __FUNCTION__);
    } else {
      eprintf("+ (%s) Correct login\n", __FUNCTION__);
    }
    break;

  case GET_USER_BY_NAME:
    ret = get_user_by_name(&sg_ctx, msg->key, (login_t **)&value);
    resp->ret = ret;
    resp->value_len = 0;
    if (ret) {
      eprintf("+ (%s) get_user_by_name failed with %d\n", __FUNCTION__, ret);
      resp->ret = 69; // TODO set better return value
      break;
    }
    if (sizeof(login_t) < resp->value_len_max) {
      memcpy(resp->value, (login_t *)value, sizeof(login_t));
      resp->value_len = sizeof(login_t);
    } else {
      eprintf("+ (%s) Error sizeof(login_t) %d >= resp->value_len_max %d\n",
              __FUNCTION__, sizeof(login_t), resp->value_len_max);
      resp->value_len = 0;
      resp->ret = 69; // TODO set better return value
    }
    free(value);
    break;

  case GET_USER_BY_ID:
    tmp = atoi(msg->key);
    ret = get_user_by_id(&sg_ctx, tmp, (login_t **)&value);
    resp->ret = ret;
    if (sizeof(login_t) < resp->value_len_max) {
      memcpy(resp->value, (login_t *)value, sizeof(login_t));
      resp->value_len = sizeof(login_t);
    } else {
      resp->value_len = 0;
      resp->ret = 1; // TODO set better return value
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

