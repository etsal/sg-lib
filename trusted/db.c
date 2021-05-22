#include "attester.h"   // ra_tls_options
#include "bearssl_wrapper.h"
#include "db.h"
#include "errlist.h"
#include "sg_common.h"
#include "sg_t.h"       // Boundary calls (OCALLS)
#include "sg_util.h"    // Sealing functions
#include "xmem.h"

//#define DEBUG_DB 1
static void int_to_str(uint64_t x, int type, char *str);
static int load_account(db_ctx_t *db, const char *username, const char *password);
static int get_update_len_db(db_ctx_t *db, size_t *len);
static int get_update_db(db_ctx_t *db, uint8_t *buf, size_t len);
static void apply_update_db(db_ctx_t *db, uint8_t *buf, size_t len);

static void 
int_to_str(uint64_t x, int type, char *str)
{
	char buf[20] = { 0 };
	int len = 0;

	switch(type) {
		case 8:
			len = 3;
			break;
		case 16:
			len = 5;
			break;
		case 32:
			len = 10;
			break;
		case 64:
			len = 19;
			break;
		default:
			len = 3;
	}

	buf[len--] = '\0';
	while (len) {
		buf[len--] = x%10 + '0';
		x = x/10;
	}

	memcpy(str, buf, strlen(str));
}

void 
db_print(db_ctx_t *db, void(*format)(const void *data))
{
    print_fmt_store(&db->table, format);
}

void
init_db(db_ctx_t *db, const char *filename, const char *username,
    const char *password)
{
#ifdef DEBUG_DB
    eprintf("\t+ Initializing database\n");
#endif

	// Set database file
	if (strlen(filename) > MAX_FILENAME) {
		eprintf("ERROR: filename too large");
		return;
	}
	strcpy(db->filename, filename);

	// Attempt to load database
	int ret = 1; // load_account(db, username, password);

	// If database failed to load just set the kv-store to 0
	if (ret) {
		init_store(&db->table, 1);
		db->accounts = NULL;
		db->serial_buf_len = 0;
		db->serial_buf = NULL;
		db->is_init = 1;
#ifdef DEBUG_DB
		eprintf("\t+ No account loaded, initializing empty table\n");
#endif
	}

#ifdef DEBUG_DB
//    edividerWithText("Current Table");
//	print_store(&db->table);
//    edivider();
    eprintf("\t+ Initialization complete.\n");
#endif
}

int
put_str_db(db_ctx_t *db, char *key, const void *value, size_t len)
{
	return put_store(&db->table, key, value, len);
}

int
get_str_db(db_ctx_t *db, char *key, void *value, size_t len)
{
	size_t new_len = len;
	int ret = get_store(&db->table, key, value, &new_len);
	return ret ? new_len : ret;
}

int
put_U64_db(db_ctx_t *db, uint64_t key, const void *value, size_t len)
{
	char key_str[20] = { 0 };
	int_to_str(key, 64, key_str);
	return put_store(&db->table, key_str, value, len);
}

int
get_U64_db(db_ctx_t *db, uint64_t key, void *value, size_t len)
{
	size_t new_len = len;
	char key_str[20] = { 0 };
	int_to_str(key, 64, key_str);
	int ret = get_store(&db->table, key_str, value, &new_len);
	return ret ? new_len : ret; 
}
/*
 * @return : 0 on success, >0 else
 */
int
db_load(db_ctx_t *db, const char *filename)
{	
	uint8_t *buf = NULL;
	size_t len = 0;
	int ret = unseal(filename, &buf, &len);
	if (ret) {
#if DEBUG_DB
        eprintf("\t+ %s: Error, unseal returned 0x%08x\n", __FUNCTION__, ret);
#endif
        return ret;
	}

#if DEBUG_DB
	edividerWithText("Unsealed Table");
	eprintf("filename: %d length : %d\n", filename, len);
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
int
db_save(db_ctx_t *db, const char *filename)
{
	uint8_t *buf;
	size_t len;
	int is_new = 0;

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
    int ret = seal(filename, buf, len);
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
int
db_get_update_len(db_ctx_t *db, size_t *len)
{
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
int
db_get_update(db_ctx_t *db, uint8_t *buf, size_t len)
{
	assert(len == db->serial_buf_len);
	if (db->serial_buf_len > 0) {
		memcpy(buf, db->serial_buf, db->serial_buf_len);
	}
	return 0;
}

void
apply_update_db(db_ctx_t *db, uint8_t *buf, size_t len)
{
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
