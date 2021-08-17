#include <sys/stat.h>
#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "buffer.h"
#include "errlist.h"
#include "sg_common.h"

//#define DEBUG_FILEIO 1

buf_uint8_t gb;
static int get_file_len(const char *filename, int *err);

/* List containting open files */
static struct open_file {
  int fd;
  FILE *fp;
};

static struct open_file files[10];
static int num_files = 0;

static FILE* find_open_file(int fd) {
  for (int i=0; i<num_files; ++i) {
    if (files[i].fd == fd) return files[i].fp;
  }
  return NULL;
}
/**/


/*
 * @param filename to open and return fd to
 */
int ocall_fopen(const char *filepath, const char *mode) {
  assert(num_files+1 < 10);

  FILE *fp = fopen(filepath, mode);
  if (fp != NULL) {
    files[num_files].fd = fileno(fp);
    files[num_files].fp = fp; 
    num_files++;
    return fileno(fp);
  } 

  return 0;
}

/* returns strlen(buf) on success, errno otherwise */
int ocall_fwrite(const char *buf, int fd) {
  FILE *fp = find_open_file(fd);
  if (fp == NULL) return EBADF;

//  eprintf("\t+ (%s) fwrite called with '%s' strlen(buf) = %d\n", __FUNCTION__, buf, strlen(buf));

  int ret = fwrite((const void *)buf, sizeof(char), strlen(buf), fp);

//  eprintf("\t+ (%s) fwrite returned with ret=%d and errno=%d\n", __FUNCTION__, strlen(buf), errno);
  fflush(fp);
//  fclose(fp);

  if (ret != strlen(buf)) return errno;
  return ret;
}

/* returns 0 on success, errno otherwise */
int ocall_fclose(int fd) {
  FILE *fp = find_open_file(fd);
  if (fp == NULL) return EBADF; 
  int ret = fclose(fp);
  if (ret != 0) return errno;
  return ret;
}

/*
 * @param: Returns 0 on success
 */
int ocall_access(const char *filename) {
  int ret = access(filename, F_OK);
  return ret;
}

/*
 *
 * @return: Returns 0 on success, >0 (errno) else
 */
int ocall_store(const char *filename, const uint8_t *buf, size_t len) {
  int fd, ret = 0;
  FILE *fp = fopen(filename, "w");
  if (fp == NULL) {
    // Create the file
    fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY);
    if (fd > 0) {
      ret = write(fd, buf, len);
      close(fd);
#ifdef DEBUG_FILEIO
      printf("\t + (%s) write errno = %d, ret = %d, len = %d\n", __FUNCTION__,
             errno, ret, len);
#endif
      return (ret == len) ? 0 : errno;
    }
#ifdef DEBUG_FILEIO
    printf("\t + (%s) open errno = %d\n", __FUNCTION__, errno);
#endif
    return errno;
  }
  ret = fwrite((uint8_t *)buf, sizeof(uint8_t), len, fp);
#ifdef DEBUG_FILEIO
  printf("\t + (%s) fwrite ret = %d, len = %d\n", __FUNCTION__, ret, len);
#endif
  fclose(fp);
  ret = (ret == len) ? 0 : errno;
  return ret;
}

/*
 * @param *len : set to 0 if file dne, >0 otherwise
 * @return : 0 on success, >0 else
 */
int ocall_load_len(const char *filename, size_t *len) {
  int err = 0;
  int ret = get_file_len(filename, &err);
  if (ret < 0) {
    return err;
  }
  *len = ret;
  return 0;
}

/*
 * @return : 0 on success, >0 else
 * Fails if trying to load empty file
 */
int ocall_load(const char *filename, uint8_t *buf, size_t len) {
  int ret = 0;
  uint8_t *tmp = NULL;

  // Check if file exists
  assert(access(filename, F_OK) == 0);
  assert(len == get_file_len(filename, &ret));
  assert(len != 0);

  // Open file
  FILE *fp = fopen(filename, "r");
  if (fp == NULL) {
    return ER_FOPEN;
  }

  // Clear global buffer
  buf_expand_as_needed(&gb, len);

#ifdef DEBUG_FILEIO
  edividerWithText("ocall_load");
  eprintf("file length: %d\n", len);
  eprintf("global buffer capacity: %d\n", gb.capacity);
#endif

  // Allocate and read
  ret = fread(gb.data, sizeof(uint8_t), len, fp);
  if (ret != sizeof(uint8_t) * (len)) {
#ifdef DEBUG_FILEIO
    eprintf("fread returned %d, expected %d\n", ret, len * sizeof(uint8_t));
#endif
    fclose(fp);
    memset(buf, 0, len);
    return ER_IO;
  }

#ifdef DEBUG_FILEIO
  eprintf("Loaded data : %s\n", hexstring(gb.data, len));
  edivider();
#endif

  // The edge routine will allocate&copy this buffer into enclave
  // memory. So we can pass it a pointer from app memory.
  memcpy(buf, gb.data, len);
  return 0;
}

int ocall_write(const int *fd, const unsigned char *buf, size_t len) {
#if DEBUG_FILEIO
  edividerWithText("ocall_write() : Write Buffer Content");
  eprintf("%s \n", hexstring(buf, len));
  edivider();
#endif
  for (;;) {
    ssize_t wlen;
    wlen = write(*fd, buf, len);
    if (wlen <= 0) {
      if (wlen < 0 && errno == EINTR) {
        continue;
      }
      return -1;
    }
    return (int)wlen;
  }
}

int ocall_read(const int *fd, unsigned char *buf, size_t len) {
  for (;;) {
    int rlen = read(*fd, buf, len);
    if (rlen <= 0) {
      if (rlen < 0 && errno == EINTR) {
        continue;
      }
      return -1;
    }
#if DEBUG_FILEIO
    edividerWithText("ocall_read() : Read Buffer Content");
    eprintf("%s \n", hexstring(buf, len));
    edivider();
#endif
    return (int)rlen;
  }
}

int ocall_close(int fd) { close(fd); }

/* Helpers */

/*
 * @return : -1 on error, >0 else
 *
 */
int get_file_len(const char *filename, int *err) {
  int ret, len = 0;
  uint8_t *tmp = NULL;
  FILE *fp = fopen(filename, "r");
  if (fp == NULL) {
    goto set_errno;
  }
  // Find size of file
  ret = fseek(fp, 0, SEEK_END);
  if (ret) {
    fclose(fp);
    goto set_errno;
  }
  len = ftell(fp);
  if (len > SIZE_MAX) {
    fclose(fp);
    errno = EFBIG;
    goto set_errno;
  }
  // Reset fp
  fseek(fp, 0, SEEK_SET);
  fclose(fp);
  ret = len;
  *err = 0;
exit:
  return ret;
set_errno: // Set err and return -1
  switch (errno) {
  case ENOENT:
    *err = ER_NOEXIST;
    break;
  case EACCES:
    *err = ER_PERM;
    break;
  case EFBIG:
    *err = ER_FBIG;
  default:
    *err = ER_IO;
    break;
  }
  ret = -1;
  goto exit;
}
