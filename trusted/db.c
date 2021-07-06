#include "db.h"
#include "attester.h" // ra_tls_options
#include "bearssl_wrapper.h"
#include "errlist.h"
#include "sg_common.h"
#include "sg_t.h"    // Boundary calls (OCALLS)
#include "sg_util.h" // Sealing functions
#include "xmem.h"

#define DEBUG_DB 1
static int load_account(db_ctx_t *db, const char *username,
                        const char *password);
static int get_update_len_db(db_ctx_t *db, size_t *len);
static int get_update_db(db_ctx_t *db, uint8_t *buf, size_t len);
static void apply_update_db(db_ctx_t *db, uint8_t *buf, size_t len);

void db_print(db_ctx_t *db, void (*format)(const void *data)) {
  print_fmt_store(&db->table, format);
}

int init_new_db(db_ctx_t *db, const char *filename)
{
  if (filename == NULL || strlen(filename) > MAX_FILENAME) {
    eprintf("ERROR: Db filename too large/NULL");
    return 1;
  }
  strcpy(db->db_filename, filename);
  init_store(&db->table, 1);
  db->accounts = NULL;
  db->serial_buf_len = 0;
  db->serial_buf = NULL;
  db->is_init = 1;
  return 0;
}

int put_db(db_ctx_t *db, const char *key, const void *value, size_t len) {
  return put_store(&db->table, key, value, len);
}

int get_db(db_ctx_t *db, const char *key, void **value, size_t *len) {
  return get_store(&db->table, key, value, len);
}

/*
 * @return : 0 on success, >0 else
 */
int db_load(db_ctx_t *db) {
  eprintf("+ (%s - %d)\n", __FUNCTION__, __LINE__);
  uint8_t *buf = NULL;
  size_t len = 0;
  int ret;

  if (db->db_filename == NULL) {
    eprintf("db filename NULL\n");
    return 1;
  }

  ret = unseal(db->db_filename, &buf, &len);
  if (ret) {
#if DEBUG_DB
    eprintf("\t+ %s: Error, unseal returned 0x%08x\n", __FUNCTION__, ret);
#endif
    return ret;
  }

#if DEBUG_DB
  edividerWithText("Unsealed Table");
  eprintf("filename: %d length : %d\n", db->db_filename, len);
  eprintf("%s\n", hexstring(buf, len));
  edivider();
#endif
  // Deserialize table
  deserialize_store(&db->table, buf, len);

#if DEBUG_DB
  edividerWithText("Table");
  print_store(&db->table);
  edivider();
#endif

  free(buf);
  return 0;
}

/* TODO: add password protection
 * @return : 0 on success, >0 else
 */
int db_save(db_ctx_t *db) {
  eprintf("+ (%s - %d)\n", __FUNCTION__, __LINE__);
  uint8_t *buf;
  size_t len;
  int is_new = 0;
  int ret;
#if DEBUG_DB
  eprintf("\t+ Saving current table\n");
  edividerWithText("Current Table");
  print_store(&db->table);
  edivider();
#endif

  serialize_store(&db->table, &buf, &len);
  if (!buf) {
    return ER_SERIAL;
  }

#if DEBUG_DB
//	edividerWithText("Serialized Table");
//	eprintf("%s\n", hexstring(buf, len));
//	edivider();
#endif

  /*
      // Get filename to save serialized table to
          const char *tablefile = find_strmap(db->accounts, username);
          if (!tablefile) {
                  tablefile = "/tmp/testaccount.db";
                  is_new = 1;
          }
  */
  // Seal table

  if (db->db_filename == NULL) {
    eprintf("db filename NULL\n");
    return 1;
  }

  ret = seal(db->db_filename, buf, len);
  /*
      // Insert <username, account_file> to account db
      if (is_new) {
              assert(insert_strmap(&db->accounts, username, tablefile));
      }
      free(buf);
  */

  free(buf);
  return ret;
}

/* Sets len to the length of the serialized kvcrdt, also calculated
serialization stores it in account buffer
 */
int db_get_update_len(db_ctx_t *db, size_t *len) {
  if (is_empty_store(&db->table)) {
    db->serial_buf_len = 0;
  } else {
    xfree(db->serial_buf);
    serialize_store(&db->table, &db->serial_buf, &db->serial_buf_len);
  }
  *len = db->serial_buf_len;
  return 0;
}

/* MUST call get_serialized_update_len_db() before this function
 */
int db_get_update(db_ctx_t *db, uint8_t *buf, size_t len) {
  assert(len == db->serial_buf_len);
  if (db->serial_buf_len > 0) {
    memcpy(buf, db->serial_buf, db->serial_buf_len);
  }
  return 0;
}

void apply_update_db(db_ctx_t *db, uint8_t *buf, size_t len) {
  table_t table;
  // Deserialize
  init_store(&table, 0);
  deserialize_store(&table, buf, len);
#if DEBUG_DB
  lprintf("Foreign Table:\n");
  print_store(&table); // prints to log

  lprintf("Local Table:\n");
  print_store(&db->table); // prints to log
#endif
  merge_store(&db->table, &table);
#if DEBUG_DB
  lprintf("Local Table After Merge:\n");
  print_store(&db->table); // prints to log
#endif
  free_store(&table);
}

