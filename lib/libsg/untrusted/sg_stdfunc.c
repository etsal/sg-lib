#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // sleep

#include "assert.h"
#include "sg_u.h" //fprint()

extern FILE *log_fp;

void ocall_atoi(const char *str, int *str_ret) { *str_ret = atoi(str); }

void ocall_sleep(int time) { sleep(time); }

void ocall_eprintf(const char *str) {
  fprintf(stderr, str, strlen(str));
  return;
}

void ocall_lprintf(const char *str) {
  //	assert(log_fp);
  //	fprintf(log_fp, str, strlen(str));
  return;
}

void ocall_exit(int s) {
  exit(s);
  return;
}

/* OCall functions */
