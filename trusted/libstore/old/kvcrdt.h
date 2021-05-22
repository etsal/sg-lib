#ifndef __KVCRDT_TABLE_H__
#define __KVCRDT_TABLE_H__

//#include <rpc/rpc.h>
#include "uthash/src/uthash.h"
#include "vvec.h"

#define MAX_VALUE_LEN 4096

// typedef enum kvcrdt_op { KVCRDT_ENCODE=XDR_ENCODE, KVCRDT_DECODE=XDR_DECODE }
// kvcrdt_op_t;

typedef struct kvcrdt_pair {
  uint64_t key;
  size_t value_len;
  void *value;
  vvec_t versions; /* Version vector per entry */
  UT_hash_handle hh;
} kvcrdt_pair_t;

typedef struct kvcrdt_table {
  uint64_t uid; /* Uid per table */
  kvcrdt_pair_t *pairs;
  vvec_t versions; /* Version vector per table */
} kvcrdt_table_t;

/* KV Functions */
void init_kvcrdt(kvcrdt_table_t *table, uint64_t uid);
void init_empty_kvcrdt(kvcrdt_table_t *table); /* Sets any pointers to null */
int add_kvcrdt(kvcrdt_table_t *table, uint64_t key, const void *value,
               size_t value_len);
int find_kvcrdt(kvcrdt_table_t *table, uint64_t key, void *value, size_t value_len);

int remove_kvcrdt(kvcrdt_table_t *table, uint64_t key);
void free_kvcrdt(kvcrdt_table_t *table);
int is_empty_kvcrdt(kvcrdt_table_t *table);


/* CRDT Functions */
void merge_kvcrdt(kvcrdt_table_t *local_set, kvcrdt_table_t *remote_set);

/* Serialization Functions */
/*
int serial_kvcrdt(XDR *xdrs, kvcrdt_table_t *objp);
int deserial_kvcrdt(XDR *xdrs, kvcrdt_table_t *objp);
*/

void serial_kvcrdt(kvcrdt_table_t *table, uint8_t **buf, size_t *len);
void deserial_kvcrdt(kvcrdt_table_t *table, uint8_t *buf, size_t len);

/* Testing Functions */
void print_kvcrdt(kvcrdt_table_t *table);
void print_fmt_kvcrdt(kvcrdt_table_t *table, void(*format)(const void *data));
void add_pair_kvcrdt(kvcrdt_table_t *table, kvcrdt_pair_t *pair);

#endif
