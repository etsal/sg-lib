#include "Enclave_t.h"
#include "sg.h"
#include <string.h>

sg_ctx_t sg_ctx;

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

