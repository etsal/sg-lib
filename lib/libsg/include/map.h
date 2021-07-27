#ifndef __MAP_H__
#define __MAP_H__

#if defined(__APP__)
#include <stdlib.h>
#endif
#if defined(__ENCLAVE__)
#include "sg_stdfunc.h"
#endif

#include "uthash/src/uthash.h"

#define STRMAP_MAX_ELEM_LEN 128

typedef struct strmap_entry {
	char first[128];
	char second[128];
	UT_hash_handle hh;
} strmap_entry_t;

typedef strmap_entry_t *strmap_t;
void free_strmap(strmap_t *map);
int insert_strmap(strmap_t *map, const char *str1, const char *str2);
const char *find_strmap(strmap_t map, const char *first);
void serialize_strmap(strmap_t map, uint8_t **buf, size_t *len);
void deserialize_strmap(strmap_t *map, uint8_t *bytes, size_t len);
void eprint_strmap(strmap_t map);

#endif
