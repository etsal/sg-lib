#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "sgx_urts.h"     /* sgx_launch_token_t */

#include "Enclave_u.h"
#include "sg_interface.h"
#include "sg_app.h"

//const char *config_path = "config.ini";
#define CONFIG_PATH "config.ini"
sgx_enclave_id_t global_eid = 0;

extern void *process();

static void *listen_for_exit() {
  char c;
  while(1) {
    c = fgetc(stdin);
    if (c == 'e') {
      return NULL;
    }
  }
}

sgx_status_t initialize_enclave(void) {
  sgx_launch_token_t token = {0};
  int updated = 0;
  sgx_status_t status = sgx_create_enclave("libenclave.signed.so", 1, &token,
                                           &updated, &global_eid, NULL);
  return status;
}

int main(int argc, const char *argv[]) {
  const char *path;
  sgx_status_t status;
  pthread_t tid, tid2;
  int ret, ret2;

  if (argc == 2) {
    path = argv[1];
  } else {
    path = CONFIG_PATH;
  }

  status = initialize_enclave();
  if (status) {
    printf("Error %08x @ %d\n", status, __LINE__);
    exit(1);
  }

  status = ecall_test_policy(global_eid);

  return ret;
}

