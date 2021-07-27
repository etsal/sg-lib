#include "buffer.h"
//#include "sg_common.h"

// TODO: change realloc to xrealloc
int
buf_expand_(char **data, int *length, int *capacity, int memsz, int expand_to)
{
	if (*capacity < expand_to) {
		void *ptr;
		int n = *capacity;
		do {
			// eprintf("cap %d, expand_to %d\n", n, expand_to);
			n = (n == 0) ? 1 : n << 1;
		} while (n <
		    expand_to); // really want the capacity to be a power of 2
		ptr = realloc(*data, n * memsz);
		if (ptr == NULL)
			return -1;
		*data = ptr;
		*capacity = n;
	}
	return 0;
}
