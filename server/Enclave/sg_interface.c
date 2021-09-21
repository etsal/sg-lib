#include "sg.h"
#include "policy.h"

extern sg_ctx_t sg_ctx;

int ecall_init_sg(void *config, size_t config_len) {
  init_sg_with_policy(&sg_ctx, config, config_len);
  //init_sg_with_policy(&sg_ctx);
  return 0;
}

int ecall_recieve_connections_sg() {
   recieve_connections_sg(&sg_ctx);
  return 0;
}

int ecall_initiate_connections_sg() {
  initiate_connections_sg(&sg_ctx);
  return 0;
}

int ecall_verify_connections_sg() {
  return verify_connections_sg(&sg_ctx);
}

int ecall_poll_and_process_updates() {
  poll_and_process_updates_sg(&sg_ctx);
  return 0;
}


