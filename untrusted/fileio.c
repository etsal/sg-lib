#include <sys/types.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "buffer.h"
#include "sg_common.h"
#include "sg_config.h"
#include "errlist.h"

//#define DEBUG_FILEIO 1

buf_uint8_t gb;

static int get_file_len(const char *filename, int *err);


int ocall_load_config(const char *filename, config_ctx_t *ctx)
{
// TODO: implement file parsing (maybe in C++)
    char statefilename[] = "/opt/instance/dump.sg";
    char policyfilename[] = "/opt/instance/policy.txt";

    strcpy(ctx->statefilename, statefilename);
    strcpy(ctx->policyfilename, policyfilename);
    
    return 0;
}


/*
 * @param: Returns 0 on success
 */
int
ocall_access(const char *filename)
{
    int ret = access(filename, F_OK);
    return ret;
}


/*
 *
 * @return: Returns 0 on success, >0 else
 */
int
ocall_store(const char *filename, const uint8_t *buf, size_t len)
{
	int ret = 0;
	FILE *fp = fopen(filename, "w");
	if (fp == NULL) {
		// Create the file
		int fd = creat(filename, S_IRUSR | S_IWUSR);
		if (fd) {
			ret = write(fd, buf, len);
			close(fd);
			return (ret == len) ? 0 : ER_IO;
		}
		return ER_FCREATE;
	}
	ret = fwrite((uint8_t *)buf, sizeof(uint8_t), len, fp);
	fclose(fp);
	ret = (ret == len) ? 0 : ER_IO;
	return ret;
}

/*
 * @param *len : set to 0 if file dne, >0 otherwise
 * @return : 0 on success, >0 else
 */
int
ocall_load_len(const char *filename, size_t *len)
{
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
int
ocall_load(const char *filename, uint8_t *buf, size_t len)
{
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

int
ocall_write(const int *fd, const unsigned char *buf, size_t len)
{
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

int
ocall_read(const int *fd, unsigned char *buf, size_t len)
{
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

int
ocall_close(int fd)
{
	close(fd);
}

/* Helpers */

/*
 * @return : -1 on error, >0 else
 *
 */
int
get_file_len(const char *filename, int *err)
{
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