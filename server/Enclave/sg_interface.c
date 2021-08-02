#include "sg.h"

extern sg_ctx_t sg_ctx;

int ecall_init_sg(const char *config_str, size_t config_str_len) {
  init_sg(&sg_ctx, config_str, config_str_len);
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


