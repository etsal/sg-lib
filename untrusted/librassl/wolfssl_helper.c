#include <sys/time.h>
#include <sys/socket.h>

#include "sg_u.h"

static double current_time() {
  struct timeval tv;
  gettimeofday(&tv,NULL);
  return (double)(1000000 * tv.tv_sec + tv.tv_usec)/1000000.0;
}

void ocall_current_time(double* time) {
    if(!time) return;
    *time = current_time();
    return;
}

void ocall_low_res_time(int* time) {
    struct timeval tv;
    if(!time) return;
    *time = tv.tv_sec;
    return;
}

size_t ocall_recv(int sockfd, void *buf, size_t len, int flags) {
    return recv(sockfd, buf, len, flags);
}

size_t ocall_send(int sockfd, const void *buf, size_t len, int flags) {
    return send(sockfd, buf, len, flags);
}
