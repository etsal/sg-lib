#ifndef __XMEM_H__
#define __XMEM_H__

#include <stdio.h>
#include <stdlib.h>

#if defined(__ENCLAVE__)
#include "sg_stdfunc.h"
#endif

#define ZERO_AND_FREE(x, sz)      \
	do {                      \
		memset(x, 0, sz); \
		xfree(x);         \
		x = NULL;         \
	} while (0)

void *xmalloc(size_t bytes);
void xfree(void *ptr);

#endif
