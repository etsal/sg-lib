
#include "xmem.h"

#ifdef __APP__
#include <stdlib.h>
#endif
#ifdef __ENCLAVE__
#include "sg_stdfunc.h"
#endif

void *
xmalloc(size_t bytes)
{
	if (bytes == 0)
		return NULL;

	void *ptr = malloc(bytes);
	if (ptr == NULL) {
		perror("malloc");
		exit(1);
	}
	return ptr;
}

void
xfree(void *ptr)
{
	if (ptr)
		free(ptr);
	ptr = NULL;
}
