#ifndef __FILEIO_H__
#define __FILEIO_H__

#include <stdint.h>
/* This header is useful for enclave functions that use these functions
 * but dont want to include the entire edger generated file.
 */

int ocall_access(const char *filename);
int ocall_store(const char *filename, const uint8_t *buf, size_t len);
int ocall_load_len(const char *filename, size_t *len);
int ocall_load(const char *filename, uint8_t *buf, size_t len);

int ocall_write(const int *fd, const unsigned char *buf, size_t len);
int ocall_read(const int *fd, unsigned char *buf, size_t len);
int ocall_close(int fd);
int ocall_fopen(const char *filepath, const char *mode);
int ocall_fwrite(const char *buf, int fd);
int ocall_fclose(int fd);

#endif
