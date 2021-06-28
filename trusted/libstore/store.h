#ifndef __STORE_H__
#define __STORE_H__

#include "uthash/src/uthash.h"
#include "store.pb-c.h"
#include "vvec.h"

#define MAX_KEY_LEN 128
#define MAX_VALUE_LEN 4096

typedef struct entry {
    char *key;
	void *value;	
	size_t value_len;
	vvec_t versions; /* Version vector per entry */
	UT_hash_handle hh;
} entry_t;

typedef struct table {
	uint64_t uid; /* Uid per table */
	entry_t *entries;
	vvec_t versions; /* Version vector per table */
} table_t;

/* KV Functions */
void init_store(table_t *table, uint64_t uid);
int put_store(table_t *table, const char *key, const void *value, size_t value_len);
int get_store(table_t *table, const char *key, void *value, size_t *value_len);
int get_store_ptr(table_t *table, const char *key, void **value);

void free_store(table_t *table);
int is_empty_store(table_t *table);

/* CRDT Functions */
void merge_store(table_t *local_set, table_t *remote_set);

/* Serialization Functions */
void serialize_store(table_t *table, uint8_t **buf, size_t *len);
void deserialize_store(table_t *table, uint8_t *buf, size_t len);
void protobuf_pack_store(table_t *table, Table *t);
void protobuf_free_packed_store(Table *t);
void protobuf_unpack_store(table_t *table, Table *t);

/* Testing Functions */
void print_store(table_t *table);
void print_fmt_store(table_t *table, void (*format)(const void *data));
void add_entry_store(table_t *table, entry_t *entry);

#endif
