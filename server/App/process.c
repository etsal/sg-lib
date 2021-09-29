#include <errno.h>
#include <stdio.h>
#include <sys/select.h>

#include "Enclave_u.h"
#include "ipc_util.h"
#include "sg_defs.h"

#define DEBUG_PROCESS 1
extern sgx_enclave_id_t global_eid;

/* Holds the function to be called if the fd
 * is ready to process updates
 * Do we even need this?
 */
void *process() {
  int ipc_fd, max_fd;
  int fds[MAX_NODES + 1];
  int check_fds[MAX_NODES + 1];
  fd_set read_fds;
  size_t fds_len, num_check = 0;
  sgx_status_t status;
  int ret, i;

  ipc_fd = prepare_ipc_socket();
#ifdef DEBUG_PROCESS
  if (!(ipc_fd > 0)) {
    printf("\t+ (%s) Failed to create ipc socket\n", __FUNCTION__);
  }
#endif

  status =
      ecall_get_connection_fds(global_eid, &ret, &fds[1], MAX_NODES, &fds_len);
#ifdef DEBUG_PROCESS
  if (fds_len == 0) {
    printf("\t+ (%s) Not receiving updates from nodes ...\n", __FUNCTION__);
  }
  if (status != SGX_SUCCESS) {
    printf("SGX error\n");
    return NULL;
  }
#endif

  // Set the first entry to be the ipc fd
  fds[0] = ipc_fd;
  fds_len += 1;

  while (1) {
#ifdef DEBUG_PROCESS
  printf("\n\n+ Processing ...\n");
#endif


    // Prepare read set
    max_fd = 0;
    FD_ZERO(&read_fds);

    for (i = 0; i < fds_len; ++i) {
      max_fd = (max_fd < fds[i]) ? fds[i] : max_fd;
      if (fds[i] > 0)
        FD_SET(fds[i], &read_fds);
    }
    max_fd += 1;


#ifdef DEBUG_PROCESS
/*
  printf("+ (%s) active fds :\n", __FUNCTION__);
  for (i = 0; i < fds_len; ++i) {
    printf("%d, ", fds[i]);
  }
  printf("\n");
*/
#endif

    // Do select()
    ret = select(max_fd, &read_fds, NULL, NULL, NULL);
    switch (ret) {
    case -1:
      perror("select()");
      return NULL;
    case 0:
      printf("select() returned 0\n");
      return NULL;
    default:
      // ipcs messages
      if (FD_ISSET(ipc_fd, &read_fds)) {
        ret = process_ipc_message(ipc_fd);
      }

      // update messages
      num_check = 0;
      memset(check_fds, 0, MAX_NODES + 1);
      for (i = 1; i < fds_len; ++i) {
        if (fds[i] > 0 && FD_ISSET(fds[i], &read_fds)) {
          printf("+ (%s) Update message recieved from fd = %d\n", __FUNCTION__, fds[i]);
          check_fds[num_check++] = fds[i];
        }
      }
#ifdef DEBUG_PROCESS
/*
      printf("check_fds: ");
      for (i=0; i<num_check; ++i) {
        printf("%d, ", check_fds[i]);
      }
      printf("\n");
*/
#endif
      if (num_check) {
        status = ecall_process_updates_sg(global_eid, &ret, check_fds, num_check);
      }
    }
  } // while(1)
}

