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

int generate_random_number() {
  ocall_print("Processing random number generation...");
  return 42;
}



/*
int generate_random_number() {
    ocall_print("Processing random number generation...");

    char test2[] = "/opt/instance/sg.db";

    int x = strlen(test2);
    ocall_print("Test\n");

   char test[1023];
   memcpy(test2, test, 10);
   test[10] = '\0';

    ocall_print("Here\n");

 //   init_sg(&sg_ctx, "test.txt");

    return 42;
}
*/
