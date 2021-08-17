#include <limits.h> //This == #include <sys/limits.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include <sgx_error.h>

#include "sg_log.h"
#include "../fileio_t.h"

//#define DEBUG_SG_LOG 1
#ifdef DEBUG_SG_LOG
#include "sg_common.h"
#endif

static int log_fd = 0;

/* Truncates file at filepath */
void init_log(const char *filepath) {
#ifdef DEBUG_SG_LOG
  eprintf("\t\t+ (%s) Log file : %s\n", __FUNCTION__, filepath);
#endif

  assert(strlen(filepath) < 1024); // TODO: should be a MACRO 
  sgx_status_t status = ocall_fopen(&log_fd, filepath, "w");

}

int write_fmt_log() {
  return 0;
}

/* Appends file at filepath i
 * returns 0 on success, errno on error
 */
int write_blob_log(const char *buf) {
  int ret;
  if (log_fd == 0) {
#ifdef DEBUG_SG_LOG
  eprintf("\t\t+ (%s) log_fd was not initalized\n", __FUNCTION__);
#endif
    return EBADF;
  }
  sgx_status_t status = ocall_fwrite(&ret, buf, log_fd);
#ifdef DEBUG_SG_LOG
  eprintf("\t\t+ (%s) ocall_fwrite returned %d expected %d\n", __FUNCTION__, ret, strlen(buf));
#endif
  if (ret == strlen(buf)) {
    ret = 0;
  }
  return ret; 
}

