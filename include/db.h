#ifndef __DB_H__
#define __DB_H__

#include "BearSSL/inc/bearssl.h"
#include "map.h"
#include "store.h"

#define DB_FILE "account.db"
#define MACHINE_CONFIG_PATH ".sg"

#define MAX_FILENAME 128

typedef struct {
  int is_init;                    // is initialized?
  char db_filename[MAX_FILENAME]; // db_filename

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
int init_new_db(db_ctx_t *db, const char *filename);

int put_str_db(db_ctx_t *db, char *key, const void *value, size_t len);
int get_str_db(db_ctx_t *db, char *key, void *value, size_t len);
int put_u64_db(db_ctx_t *db, uint64_t key, const void *value, size_t len);
int get_u64_db(db_ctx_t *db, uint64_t key, void *value, size_t len);

int db_save(db_ctx_t *db);
int db_load(db_ctx_t *db);
int db_serial(db_ctx_t *db, uint8_t **buf, size_t *len);

void db_print(db_ctx_t *db, void (*format)(const void *data));

int db_get_update_len(db_ctx_t *db, size_t *len);
int db_get_update(db_ctx_t *db, uint8_t *buf, size_t len);

#endif
