#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "sgx_urts.h"
#include "sg_interface.h"


//#include "Enclave_u.h" // only need this for ocalls

#define DEBUG_SG 1

sgx_enclave_id_t global_eid = 0;

void ocall_print(const char *str) { printf("%s\n", str); }

//void ocall_exit(int s) { exit(s); }

sgx_status_t initialize_enclave(void) {
  sgx_launch_token_t token = {0};
  int updated = 0;
  sgx_status_t status = sgx_create_enclave("libenclave.signed.so", 1, &token,
                                           &updated, &global_eid, NULL);
  return status;
}


/*
void *send_messages() {
  for (int i = 0; i < 3; ++i)
    send_message(global_eid, "HELLO");
}
*/

int main(int argc, char const *argv[]) {
  sgx_status_t status;
  int ret;

  status = initialize_enclave();
  if (status) {
    printf("Error %08x @ %d\n", status, __LINE__);
    exit(1);
  }

  ret = initialize_sg();
  if (ret) {
    printf("Error %08x @ %d\n", ret, __LINE__);
    exit(1);
  }

  ret = connect_sg();
  if (ret) {
    printf("Error %08x @ %d\n", ret, __LINE__);
    exit(1);
  }

  

  return 0;
}
