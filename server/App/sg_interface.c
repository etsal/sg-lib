#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#include "Enclave_u.h"
#include "sg.h"
#include "sgx_urts.h"

#define SLEEP_TIME 6 // Wait for cluster connections for at most

extern sgx_enclave_id_t global_eid;

int initialize_sg() {
  int ret;
  sgx_status_t status = ecall_init_sg(global_eid, &ret);
  if (status)
    return 1;
  return 0;
}

static void *recieve_connections() {
  int ret;
  sgx_status_t status = ecall_recieve_connections_sg(global_eid, &ret);
//  if (status)
//    nclude <unistd.h>return 1;
//  return 0;
}

static void *initiate_connections() {
  int ret;
  sgx_status_t status = ecall_initiate_connections_sg(global_eid, &ret);
//  if (status)
//    return 1;
//  return 0;
}

int connect_sg() {
  sgx_status_t status;
  pthread_t tid1, tid2;
  int ret, ret1, ret2;

  pthread_create(&tid1, NULL, recieve_connections, (void *)&ret1);
  pthread_create(&tid2, NULL, initiate_connections, (void *)&ret2);

  sleep(SLEEP_TIME);

  pthread_cancel(tid1);
  pthread_cancel(tid2);

  pthread_join(tid1, NULL);
  pthread_join(tid2, NULL);

  status = ecall_verify_connections_sg(global_eid, &ret);
  if (status || !ret) {
    printf("Failed to connect to cluster ... Exiting status = %08x ret = %d\n",
           status, ret);
    return 1;
  }
  return 0;
}

int run_service_sg() {
  int ret;
  sgx_status_t status = ecall_poll_and_process_updates(global_eid, &ret);
  if (status)
    return 1;
  return 0;
}
