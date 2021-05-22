#ifndef __ERRLIST_H__
#define __ERRLIST_H__

#include <stdio.h>

#include "sgx_error.h"

#define SGX_MASK 0x80000000
#define SGX_MASK_OFF 0x7FFFFFFF

#define MK_ERROR(x) (0x00000000 | (x))
#define SGX_ERROR(x) (SGX_MASK | (x))

/*
 *	These values should not collide with errno
 */
typedef enum _ret_t {
	ER_IO = MK_ERROR(0x5050),
	ER_IOSETUP = MK_ERROR(0x5051),
	ER_FCREATE = MK_ERROR(0x5052),
	ER_FOPEN = MK_ERROR(0x5053),
	ER_SGX_UNSEAL = MK_ERROR(0x5054),
	ER_SGX_SEAL = MK_ERROR(0x5055),
	ER_SERIAL = MK_ERROR(0x5056),
	ER_PERM = MK_ERROR(0x5057),
	ER_FBIG = MK_ERROR(0x5058),
	ER_NOEXIST = MK_ERROR(0x5060),
	ER_AFTEREXEC = MK_ERROR(0x5061),

	ER_ENCODING = MK_ERROR(0x5070),
	ER_DECODING = MK_ERROR(0x5071),

	ER_IAS_OK = MK_ERROR(0x5100),
	ER_IAS_BAD_REQUEST = MK_ERROR(0x5101),
	ER_IAS_BAD_RESPONSE = MK_ERROR(0x5102),
	ER_IAS_UNAUTHORIZED = MK_ERROR(0x5103),
	ER_IAS_NOT_FOUND = MK_ERROR(0x5104),
	ER_IAS_UNAVAILABLE = MK_ERROR(0x5105),
	ER_IAS_SERVER_ERR = MK_ERROR(0x5106),
	ER_IAS_BAD_CERT = MK_ERROR(0x5107),
	ER_IAS_BAD_SIGNATURE = MK_ERROR(0x5108)
} ret_t;

typedef struct _errlist {
	int err;
	const char *msg;
	const char *sug;
} errlist_t;

static errlist_t errlist[] = {
	{ ER_IO, "An error occurred while doing I/O on some file", NULL },
	{ ER_IOSETUP, " An error occurred while settng up sockets", NULL },
	{ ER_FCREATE, "An error occurred while creating a file", NULL },
	{ ER_FOPEN, "An error occurred while opening a file", NULL },
	{ ER_SGX_UNSEAL, "An error occurred when making an SGX unseal call",
	    NULL },
	{ ER_SGX_SEAL, "An error occurred when making an SGX seal call", NULL },
	{ ER_PERM,
	    "An error occurred while accessing a file, check permissions",
	    NULL },
	{ ER_FBIG, "An error occurred while acces a file, file is too large",
	    NULL },
	{ ER_SERIAL, "An error occured during serialization of some data",
	    NULL },
	{ ER_NOEXIST, "An error occured when trying to locate a data item",
	    NULL },
	{ ER_ENCODING, "An error occured when encoding data", NULL },
	{ ER_NOEXIST, "An error occured when decoding data", NULL },
	{ ER_AFTEREXEC, "Exec faile", NULL },

	{ ER_IAS_OK, "", NULL },
	{ ER_IAS_BAD_REQUEST, "Bad request sent to IAS", NULL },
	{ ER_IAS_BAD_RESPONSE, "Bad response from IAS",
	    "Check IAS API for any changes" },
	{ ER_IAS_UNAUTHORIZED, "", NULL }, { ER_IAS_NOT_FOUND, "", NULL },
	{ ER_IAS_UNAVAILABLE, "", NULL }, { ER_IAS_SERVER_ERR, "", NULL },
	{ ER_IAS_BAD_CERT, "IAS responded with invalid cert",
	    "Check that we have th most up-to-date IAS public key" },
	{ ER_IAS_BAD_SIGNATURE, "IAS responded with invalid signature",
	    "Check that we have the most up-to-date IAS public key" }
};

void eprint_err(int err);

#endif
