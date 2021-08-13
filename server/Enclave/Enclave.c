#include <string.h>

#include "Enclave_t.h"
#include "sg.h"
#include "sg_common.h"
#include "sgd_message.h"

sg_ctx_t sg_ctx;

void ecall_test() {

}

void ecall_process_request(uint8_t *data, size_t data_len, struct response_msg *resp) {
  struct request_msg *msg = (struct request_msg *)data;

  void *value = NULL;
  size_t value_len = 0;

  int ret;
  switch(msg->cmd) {
    case PUT_REQUEST:
      assert(msg->value_len < MAX_VALUE_LEN);
      ret = put_sg(&sg_ctx, msg->key, msg->value, msg->value_len);
    break;
    case GET_REQUEST:
      ret = get_sg(&sg_ctx, msg->key, &value, &value_len);
      resp->ret = ret & 0xff;
      resp->value_len = value_len;
      eprintf("\t++ (%s) get_sg() returned %d, returning %d\n", __FUNCTION__, ret, resp->ret);
      if (value_len < resp->value_len_max) {  // Only copy value if buffer has enough space
        memcpy(resp->value, value, value_len);
      }
    break;
  }
  //return ret;
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
void connect_cluster() {
  initiate_connections_sg(&sg_ctx);
}

void recieve_cluster_connections() {
  recieve_connections_sg(&sg_ctx);
}

void poll_and_process_updates() {
  poll_and_process_updates_sg(&sg_ctx);
}

int verify_cluster_connections() {
  int ret = 0;
  ret = verify_connections_sg(&sg_ctx);
  return ret;
}

void send_message(const char *msg) {
  send_msg_sg(&sg_ctx, msg); 
}

