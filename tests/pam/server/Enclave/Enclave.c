#include <string.h>

#include "Enclave_t.h"
#include "sg.h"
#include "ipc_msg.h"

sg_ctx_t sg_ctx;

void ecall_test() {

}

int ecall_process_request(uint8_t *data, size_t data_len) {
  struct msg_request *msg = (struct msg_request *)data;
  int ret;

  switch(msg->cmd) {
    case ADD_CMD:
      ret = add_user_sg(&sg_ctx, msg->key, msg->value);
    break;
    case AUTH_CMD:
      ret = auth_user_sg(&sg_ctx, msg->key, msg->value);
    break;
  }
  return ret;
}

void init() { 
  init_sg(&sg_ctx); 
}

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

