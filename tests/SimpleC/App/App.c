#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include "Enclave_u.h"
#include "sgx_urts.h"

//#include "sg_common.h" //eprintf

#define DEBUG_SG 1

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// OCall implementations
void ocall_print(const char *str) { printf("%s\n", str); }

void ocall_exit(int s) { exit(s); }

sgx_status_t initialize_enclave(void) {
  sgx_launch_token_t token = {0};
  int updated = 0;
  sgx_status_t status = sgx_create_enclave("libenclave.signed.so", 1, &token,
                                           &updated, &global_eid, NULL);
  return status;
}

void *listen_connections() {
  sgx_status_t status = recieve_cluster_connections(global_eid);
  if (status) {
  
  }
}

int main(int argc, char const *argv[]) {
  pthread_t tid;
  int ret = 0;
  sgx_status_t status = initialize_enclave();
  if (status) {
    printf("Error %08x @ %d\n", status, __LINE__);
    exit(1);
  }

  status = init(global_eid);
  if (status) {
    printf("Error %08x @ %d\n", status, __LINE__);
    exit(1);
  }

  pthread_create(&tid, NULL, listen_connections,
                 (void *)&ret); // Listen for sg connections

  status = connect_cluster(global_eid);
  if (status) {
    printf("Error %08x @ %d\n", status, __LINE__);
    goto cleanup;
  }

/*
  int random_number = 0;
  status = generate_random_number(global_eid, &random_number);
  if (status)
    goto cleanup;

  printf("Random Number from Enclave %d\n", random_number);
*/

cleanup: 
  printf("Joining server thread ...\n");
  sleep(5);
  pthread_cancel(tid);
  pthread_join(tid, NULL);

  status = verify_cluster_connections(global_eid, &ret);
  if (status || !ret) {
    printf("Failed to connect to cluster ... Exiting status = %08x ret = %d\n", status, ret);
    return 0;
  }

  status = poll_and_process_updates(global_eid);
  if (status) {
    printf("Failed when listening for updates ... Exiting\n");
    return 0;
  }

  printf("Terminating successfully!\n");

  return 0;
  /*
      if (initialize_enclave(&global_eid, NULL, "libenclave.signed.so") < 0) {
          std::cout << "Fail to initialize enclave." << std::endl;
          return 1;
      }
      int ptr;
      sgx_status_t status = generate_random_number(global_eid, &ptr);
      std::cout << status << std::endl;
      if (status != SGX_SUCCESS) {
          std::cout << "noob" << std::endl;
      }
      printf("Random number: %d\n", ptr);

      // Seal the random number
      size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(ptr);
      uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

      sgx_status_t ecall_status;
      status = seal(global_eid, &ecall_status,
              (uint8_t*)&ptr, sizeof(ptr),
              (sgx_sealed_data_t*)sealed_data, sealed_size);

      if (!is_ecall_successful(status, "Sealing failed :(", ecall_status)) {
          return 1;
      }

      int unsealed;
      status = unseal(global_eid, &ecall_status,
              (sgx_sealed_data_t*)sealed_data, sealed_size,
              (uint8_t*)&unsealed, sizeof(unsealed));

      if (!is_ecall_successful(status, "Unsealing failed :(", ecall_status)) {
          return 1;
      }

      std::cout << "Seal round trip success! Receive back " << unsealed <<
     std::endl;

      return 0;
  */
}
