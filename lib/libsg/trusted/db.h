#ifndef __DB_H__
#define __DB_H__

#include "BearSSL/inc/bearssl.h"
#include "map.h"
#include "store.h"

#define DB_FILE "account.db"
#define MACHINE_CONFIG_PATH ".sg"

typedef struct {
  int is_init;                    // is initialized?

  strmap_t accounts;         // <username, tablefile> mapping
  const char *cur_tablefile; // table filename, points to accounts memory
  table_t table;             // current table
  size_t serial_buf_len;
  uint8_t *serial_buf;
  const char *cur_username; // current username

  // NEW
  char *dbfilename;

} db_ctx_t;

// Note: init_db() is handled by sg
int init_new_db(db_ctx_t *db);

int put_db(db_ctx_t *db, const char *key, const void *value, size_t len);
int get_db(db_ctx_t *db, const char *key, void **value, size_t *len);

int save_db(db_ctx_t *db, const char *filename);
int load_db(db_ctx_t *db);

// Testing purposes
int serialize_db(db_ctx_t *db, uint8_t **buf, size_t *len);
int deserialize_db(db_ctx_t *db, uint8_t *buf, size_t len);
int compare_db(db_ctx_t *db1, db_ctx_t *db2);
int verify_db(db_ctx_t *db);

void db_print(db_ctx_t *db, void (*format)(const void *data));

int db_get_update_len(db_ctx_t *db, size_t *len);
int db_get_update(db_ctx_t *db, uint8_t *buf, size_t len);

#endif
