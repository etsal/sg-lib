#ifndef __BUFFER_H__
#define __BUFFER_H__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define buf_unpack_(v) \
	(char **)&(v)->data, &(v)->length, &(v)->capacity, sizeof(*(v)->data)

#define buf_t(T)                      \
	struct {                      \
		T *data;              \
		int length, capacity; \
	}

#define buf_init(v) memset((v), 0, sizeof(*(v)))

#define buf_deinit(v) (free((v)->data), buf_init(v))

#define buf_expand_as_needed(v, n) \
	(n > (v)->capacity ? buf_expand_(buf_unpack_(v), n) : 0)

int buf_expand_(
    char **data, int *length, int *capacity, int memsz, int expand_to);

typedef buf_t(uint8_t) buf_uint8_t;

#endif
