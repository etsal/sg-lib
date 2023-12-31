#include <assert.h>
#include <stdio.h>
#include <string.h> /* TODO: remove this after testing */

#include "sg_common.h"
#include "store.h"
#include "store.pb-c.h"
#include "tiny-regex-c/re.h"
#ifdef __ENCLAVE__
#include "sg_stdfunc.h"
#endif

//#define DEBUG_STORE 1

/*TODO: merge timestamps into vv */

static void create_entry(entry_t **entry, const char *key, const void *value,
                         size_t value_len);
static void put_entry_store(table_t *table, entry_t *entry);
static void print_entry(entry_t *entry);
static void exists_entry(table_t *table, entry_t *entry);

int compare_store(table_t *t1, table_t *t2) {
  entry_t *e, *tmp;

  if (t1->entries == NULL && t2->entries == NULL)
    return 0;

  if (t1->entries == NULL || t2->entries == NULL)
    return 1;

  HASH_ITER(hh, t1->entries, e, tmp) {
    entry_t *found = NULL;
    HASH_FIND_STR(t2->entries, e->key, found);
    if (found == NULL)
      return 1;
  }

  HASH_ITER(hh, t2->entries, e, tmp) {
    entry_t *found = NULL;
    HASH_FIND_STR(t1->entries, e->key, found);
    if (found == NULL)
      return 1;
  }

  return 0;
}

/*
 if (!table->entries)
    return 0;

  HASH_FIND_STR(table->entries, key, entry);
  if (!entry)
    return 0;

  if (*value_len < entry->value_len)
    return 0;

  memcpy(value, entry->value, entry->value_len);
  *value_len = entry->value_len;


*/

/*
 * If uid == 0, initialize an empty table
 */
void init_store(table_t *table, uint64_t uid) {
  table->uid = uid;
  table->entries = NULL;
  if (uid == 0) {
    table->versions = NULL;
  } else {
    init_vvec(&table->versions, uid);
  }
}

/* init_empty_table
void
init_table(table_t *table)
{
        table->uid      = -1;
        table->pairs    = NULL;
        table->versions = NULL;
}
*/

int is_empty_store(table_t *table) {
  if (table->uid == 0 || table->entries == NULL || table->versions == NULL)
    return 1;
  return 0;
}

static void create_entry(entry_t **entry, const char *key, const void *value,
                         size_t value_len) {
  *entry = malloc(sizeof(entry_t));
  if (!*entry) {
    return;
  }
  memset(*entry, 0, sizeof(entry_t));
  (*entry)->key = malloc(strlen(key) + 1);
  (*entry)->value = malloc(value_len);
  if (!(*entry)->key || !(*entry)->value) {
    free(*entry);
    *entry = NULL;
    return;
  }
  memcpy((*entry)->key, key, strlen(key) + 1);
  memcpy((*entry)->value, value, value_len);
  //(*entry)->key_len = strlen(key) + 1;
  (*entry)->value_len = value_len;
  (*entry)->versions = NULL;
}

/* put_store
 * The store allocates memory and copies value into it
 * return 1 on error, 0 on success
 */
int put_store(table_t *table, const char *key, const void *value,
              size_t value_len) {
  entry_t *entry = NULL;
  uint64_t ts = 0;

  // Check that the table is not empty
  assert(table->uid);

  // Check that the value is not too long
  // ++   Setting a max len makes passing value to/from enclave
  // ++   easier
  if (strlen(key) > MAX_VALUE_LEN || value_len > MAX_VALUE_LEN) {
    return 1;
  }

  // Check if key exists
  if (table->entries) {
    HASH_FIND_STR(table->entries, key, entry);
    if (entry) {
      memcpy(entry->key, key, strlen(key) + 1);
      if (value_len > entry->value_len) {
        free(entry->value);
        entry->value = malloc(value_len);
      }
      memcpy(entry->value, value, value_len);

      update_vvec(&table->versions, table->uid); // Increment kv-store clock
      ts = get_vvec(&table->versions, table->uid);
      set_vvec(&entry->versions, table->uid, ts); // Increment this key's clock

      return 0;
    }
  }

  create_entry(&entry, key, value, value_len);

  if (!entry)
    return 1;

  // Increment timestamp for table
  update_vvec(&table->versions, table->uid);

  // Increment timestamp for element
  ts = get_vvec(&table->versions, table->uid);
  add_vvec(&entry->versions, table->uid, ts);

  HASH_ADD_KEYPTR(hh, table->entries, entry->key, strlen(entry->key), entry);

  return 0;
}

/* get_store()
 * RETURNS ADDRESS OF value
 * @param **value : a void ptr that will point to value
 * @ret 0 on success, 1 on error
int get_store(table_t *table, const char *key, void **value, size_t *len) {
  entry_t *entry = NULL;
  uint64_t ts = 0;

  if (strlen(key) > MAX_KEY_LEN)
    return 1;

  if (!table->entries)
    return 1;

  HASH_FIND_STR(table->entries, key, entry);
  if (!entry) {
#ifdef DEBUG_STORE
    eprintf("++ (%s) Could not find entry with key %s\n",  __FUNCTION__, key);
#endif
    return 1;
  }

#ifdef DEBUG_STORE
  eprintf("++ (%s) Found entry with key %s\n",  __FUNCTION__, key);
#endif

  if (value == NULL)
    return 0;

  *value = entry->value;

  if (len != NULL)
    *len = entry->value_len;

  return 0;
}
*/

/* get_store()
 * RETURNS COPY OF value
 * @param **value : a void ptr that will point to value
 * @ret 0 on success, 1 on error
 */
int get_store(table_t *table, const char *key, void **value, size_t *len) {
  entry_t *entry = NULL;
  uint64_t ts = 0;

  if (strlen(key) > MAX_KEY_LEN)
    return 1;

  if (!table->entries)
    return 1;

  HASH_FIND_STR(table->entries, key, entry);
  if (!entry) {
#ifdef DEBUG_STORE
    eprintf("++ (%s) Could not find entry with key %s\n", __FUNCTION__, key);
#endif
    return 1;
  }

#ifdef DEBUG_STORE
  eprintf("++ (%s) Found entry with key %s\n", __FUNCTION__, key);
#endif

  if (value == NULL) {
    *value = NULL;
    return 0;
  }

  *value = malloc(entry->value_len + 1);
  memcpy(*value, entry->value, entry->value_len);
  *len = entry->value_len;

  return 0;
}

/* search_store()
 * RETURNS COPY OF value
 * @param **value : a void ptr that will point to value
 * @ret 0 on success, 1 on error
 */
int search_store(table_t *table, const char *regex, char **key, void **value,
                 size_t *len) {
  entry_t *entry = NULL, *tmp = NULL;
  uint64_t ts = 0;
  int match_len, match_idx = -1;

  re_t pattern = re_compile(regex);

  if (!table->entries)
    return 1;

  HASH_ITER(hh, table->entries, entry, tmp) {
    eprintf("\t\t + (%s) Entry found %s\n", __FUNCTION__, entry->key);
    match_idx = re_matchp(pattern, entry->key, &match_len);
    if (match_idx != -1) {
      break;
    }
  }

  // Did not find any keys that match the regex
  if (match_idx == -1) {
#ifdef DEBUG_STORE
    eprintf("++ (%s) Could not match regex %s with any key\n", __FUNCTION__,
            regex);
#endif
    return 1;
  }

#ifdef DEBUG_STORE
  eprintf("++ (%s) Matched regex %s to entry with key %s\n", __FUNCTION__,
          regex, entry->key);
#endif

  if (key != NULL) {
    *key = malloc(strlen(entry->key) + 1);
    memcpy(*key, entry->key, strlen(entry->key) + 1);
  }

  // Found key, but only return boolean
  if (value != NULL) {
    *value = malloc(entry->value_len + 1);
    memcpy(*value, entry->value, entry->value_len);
    *len = entry->value_len;
  }

  return 0;
}

/*
 * Does not increment the local version vector for an insert
 * to be used during a merge
 */
static void put_entry_store(table_t *table, entry_t *entry) {
  entry_t *new_entry = NULL;

  if (table->entries) {
    HASH_FIND_STR(table->entries, entry->key, new_entry);
    if (new_entry)
      return;
  }

  assert(entry->value_len < MAX_VALUE_LEN);
  create_entry(&new_entry, entry->key, entry->value, entry->value_len);
  assert(new_entry != NULL);

  // Add version to element's ts array
  uint64_t ts = get_vvec(&table->versions, table->uid);
  add_vvec(&new_entry->versions, table->uid, ts);

  HASH_ADD_KEYPTR(hh, table->entries, new_entry->key, strlen(new_entry->key),
                  new_entry);
}

/*
int
remove_kvcrdt(kvcrdt_table_t *table, uint64_t key)
{
        kvcrdt_pair_t *pair = NULL;
        version_t *v;

        if (!table->pairs)
                return 0;

        HASH_FIND_INT(table->pairs, &key, pair);
        if (!pair)
                return 0;

        HASH_DEL(table->pairs, pair);
        free_vvec(&pair->versions);
        free(pair->value);
        free(pair);

        return 1;
}
*/

static void free_entry(entry_t *entry) {
  free(entry->key);
  free(entry->value);
  free_vvec(&entry->versions);
  entry->key = NULL;
  entry->value = NULL;
}

void free_store(table_t *table) {
  entry_t *entry = NULL, *tmp = NULL;
  if (!table)
    return;
  if (table->entries) {
    HASH_ITER(hh, table->entries, entry, tmp) {
      HASH_DEL(table->entries, entry);
      free_entry(entry);
      free(entry);
      entry = NULL;
    }
  }
  assert(table->entries == NULL); // uthash should set this to NULL
  free_vvec(&table->versions);
}

void merge_store(table_t *local_set, table_t *remote_set) {
  entry_t *remote_entry, *local_entry, *next_entry;

  int do_remove = 0, do_add = 0;

  eprintf("\t+ (%s) looking for remote removes...\n", __FUNCTION__);

  // Remote removes
  HASH_ITER(hh, local_set->entries, local_entry, next_entry) {

    eprintf("\t+ (%s) local entry found (key=%s)\n", __FUNCTION__,
            local_entry->key);

    remote_entry = NULL;

    HASH_FIND_STR(remote_set->entries, local_entry->key, remote_entry);

    if (remote_entry != NULL)
      continue; // Element exists in both sets

    // If the timestamps are equal or the remote_entry ts <
    // local_entry ts -> keep the element

    // Local add is older than remote remove/ne, remove wins
    if (lt_vvec(&local_set->versions, &remote_set->versions)) {
      do_remove = 1;
    } else if (cc_vvec(&local_set->versions, &remote_set->versions)) {
      if (remote_set->uid > local_set->uid) { // Break tie, higher uid wins
        do_remove = 1;
      }
    }

    if (do_remove) {
      HASH_DEL(local_set->entries, local_entry);
      // TODO: free the key and value?
      free_vvec(&local_entry->versions);
      free_entry(local_entry);
      free(local_entry);
      do_remove = 0;
    }
  }

  eprintf("\t+ (%s) Looking for remote adds ... \n", __FUNCTION__);

  // Remote adds
  HASH_ITER(hh, remote_set->entries, remote_entry, next_entry) {
    local_entry = NULL;
    HASH_FIND_STR(local_set->entries, remote_entry->key, local_entry);

    if (local_entry != NULL)
      continue;

    eprintf("\t+ (%s) remote entry NOT found locally (key=%s)\n", __FUNCTION__,
            remote_entry->key);

    eprintf("\t+ (%s) Local set VV: ", __FUNCTION__);
    print_vvec(&local_set->versions);

    eprintf("\t+ (%s) Remote entry VV: ", __FUNCTION__);
    print_vvec(&remote_entry->versions);

    if (xor_vvec(&local_set->versions, &remote_entry->versions)) {
      do_add = 1;
    } else if (lt_vvec(&local_set->versions,
                       &remote_entry->versions)) { // Local remove/ne is older
                                                   // than remote add, add wins
      do_add = 1;
    } else if (cc_vvec(&remote_entry->versions,
                       &local_set->versions)) { // Add wins
      if (remote_set->uid > local_set->uid) {   // Break tie, higher uid wins
        do_add = 1;
      }
    }

    if (do_add) {
      put_entry_store(local_set, remote_entry);
      eprintf("\t+ (%s) Added entry to local store\n", __FUNCTION__);
      do_add = 0;
    }
  }

  eprintf("\t+ (%s) Merging version vectors ... \n", __FUNCTION__);

  // Merge version vectors
  merge_vvec(&local_set->versions, &remote_set->versions);
  eprintf("\t+ (%s) Done\n", __FUNCTION__);
}

static void print_entry(entry_t *entry) {
  int print_len = (entry->value_len < 10) ? entry->value_len : 10;
  eprintf("(%s, ", entry->key);
  eprintf("%s", hexstring(entry->value, print_len));
  if (print_len != entry->value_len)
    printf("...");
  printf(")\t");
}

void print_store(table_t *table) {
  entry_t *entry;
  eprintf("Table UID : %lu", table->uid);
  print_vvec(&table->versions);
  for (entry = table->entries; entry != NULL; entry = entry->hh.next) {
    print_entry(entry);
    print_vvec(&entry->versions);
  }
}

void print_fmt_store(table_t *table, void (*format)(const void *data)) {
  entry_t *entry;
  edividerWithText("Table");
  eprintf("UID             : %lu\n", table->uid);
  print_vvec(&table->versions);
  edivider();
  for (entry = table->entries; entry != NULL; entry = entry->hh.next) {
    eprintf("Key             : %s\n", entry->key);
    eprintf("Version Vector  : ");
    print_vvec(&entry->versions);
    eprintf("Value           : \n");
    format(entry->value);
    edivider();
  }
}

void protobuf_pack_store(table_t *table, Table *t) {
  t->uid = table->uid;
  t->n_entries = HASH_COUNT(table->entries);
  t->entries = malloc(t->n_entries * sizeof(Entry *));

  int i = 0;
  for (entry_t *e = table->entries; e != NULL; e = e->hh.next) {
    t->entries[i] = malloc(sizeof(Entry));
    entry__init(t->entries[i]);

    // Handle key
    int key_len = strlen(e->key) + 1;
    t->entries[i]->key.len = key_len; // p->key_len;
    t->entries[i]->key.data = malloc(key_len);
    memcpy(t->entries[i]->key.data, e->key, key_len);

    // Handle value
    t->entries[i]->value.len = e->value_len;
    t->entries[i]->value.data = malloc(e->value_len);
    memcpy(t->entries[i]->value.data, e->value, e->value_len);

    // Handle version vector for each kv-pair
    t->entries[i]->versions = malloc(sizeof(VersionVector));
    version_vector__init(t->entries[i]->versions);
    protobuf_pack_vvec(&e->versions, t->entries[i]->versions);

    ++i;
  }
}

void protobuf_free_packed_store(Table *t) {
  for (int i = 0; i < t->n_entries; ++i) {
    free(t->entries[i]->versions);
    free(t->entries[i]->value.data);
    free(t->entries[i]->key.data);
    free(t->entries[i]);
  }
  free(t->entries);
}

void protobuf_unpack_store(table_t *table, Table *t) {

  assert(table != NULL && t != NULL);
  if (table != NULL)
    free_store(table);

  table->uid = t->uid;

#ifdef DEBUG_STORE
  eprintf("\t+ (%s) table entries found :%d \n", __FUNCTION__, t->n_entries);
#endif

  for (int i = 0; i < t->n_entries; ++i) {
    // Create pair
    entry_t *entry = malloc(sizeof(entry_t));

    int key_len = t->entries[i]->key.len;
    entry->key = malloc(key_len);
    memcpy(entry->key, t->entries[i]->key.data, key_len);

    entry->value_len = t->entries[i]->value.len;
    entry->value = malloc(entry->value_len);
    memcpy(entry->value, t->entries[i]->value.data, entry->value_len);

    entry->versions = NULL;
    protobuf_unpack_vvec(&entry->versions, t->entries[i]->versions);
    // Insert pair into table
    HASH_ADD_KEYPTR(hh, table->entries, entry->key, strlen(entry->key), entry);
    // Immediately free vvec
    // vvec__free_unpacked(&entry->versions);
  }

  // Load the table's version vector
  protobuf_unpack_vvec(&table->versions, t->versions);
  // Immediately free vvec
  // vvec__free_unpacked(&table->versions);
}

void serialize_store(table_t *table, uint8_t **buf, size_t *len) {
  Table ptable = TABLE__INIT;
  ptable.uid = table->uid;
  ptable.n_entries = HASH_COUNT(table->entries);
  ptable.entries = malloc(ptable.n_entries * sizeof(Entry *));

#ifdef DEBUG_STORE
  eprintf("+ (%s) start\n", __FUNCTION__);
#endif

  int i = 0;
  for (entry_t *p = table->entries; p != NULL; p = p->hh.next) {

#ifdef DEBUG_STORE
    eprintf("+ (%s) entry count %d\n", __FUNCTION__, i + 1);
    eprintf("\t + key='%s', value='%s'\n", p->key,
            hexstring(p->value, p->value_len));
    eprintf("\t + key len = %d\n\n", strlen(p->key) + 1);

#endif

    ptable.entries[i] = malloc(sizeof(Entry));
    entry__init(ptable.entries[i]);

    // Handle key
    int key_len = strlen(p->key) + 1;
    ptable.entries[i]->key.len = key_len; // p->key_len;
    ptable.entries[i]->key.data = malloc(key_len);
    memcpy(ptable.entries[i]->key.data, p->key, key_len);

    // Handle value
    ptable.entries[i]->value.len = p->value_len;
    ptable.entries[i]->value.data = malloc(p->value_len);
    memcpy(ptable.entries[i]->value.data, p->value, p->value_len);

    // Handle version vector for each kv-pair
    ptable.entries[i]->versions = malloc(sizeof(VersionVector));
    version_vector__init(ptable.entries[i]->versions);
    protobuf_pack_vvec(&p->versions, ptable.entries[i]->versions);

    ++i;
  }

  // Handle version vector for table
  ptable.versions = malloc(sizeof(VersionVector));
  version_vector__init(ptable.versions);
  protobuf_pack_vvec(&table->versions, ptable.versions);

  *len = table__get_packed_size(&ptable);
  *buf = malloc(*len);

  table__pack(&ptable, *buf);

  // Free each pair
  for (i = 0; i < ptable.n_entries; ++i) {
    protobuf_free_packed_vvec(ptable.entries[i]->versions);
    free(ptable.entries[i]->versions);
    free(ptable.entries[i]->value.data);
    free(ptable.entries[i]->key.data);
    free(ptable.entries[i]);
  }
  free(ptable.entries);

  // Free table version vector
  protobuf_free_packed_vvec(ptable.versions);
  free(ptable.versions);
  return;
}

void deserialize_store(table_t *table, uint8_t *buf, size_t len) {
  Table *ptable = NULL;

  if (table == NULL) {
    eprintf("+ (%s) Error, table is null\n", __FUNCTION__);
    return;
  }

  ptable = table__unpack(NULL, len, buf);
  if (ptable == NULL) {
    eprintf("+ (%s) Error, ptable is null\n", __FUNCTION__);
    return;
  }

  init_store(table, 0);
  table->uid = ptable->uid;

#ifdef DEBUG_STORE
  eprintf("+ (%s) ptable->uid = %d %d\n", __FUNCTION__, table->uid,
          ptable->uid);
  eprintf("+ (%s) ptable->n_enries = %d\n", __FUNCTION__, ptable->n_entries);
#endif

  for (int i = 0; i < ptable->n_entries; ++i) {
    // Create pair
    entry_t *entry = malloc(sizeof(entry_t));

    int key_len = ptable->entries[i]->key.len;
    entry->key = malloc(key_len);
    memcpy(entry->key, ptable->entries[i]->key.data, key_len);

    entry->value_len = ptable->entries[i]->value.len;
    entry->value = malloc(entry->value_len);
    memcpy(entry->value, ptable->entries[i]->value.data, entry->value_len);

    entry->versions = NULL;
    protobuf_unpack_vvec(&entry->versions, ptable->entries[i]->versions);

#ifdef DEBUG_STORE
    eprintf("+ (%s) entry %d: \n", __FUNCTION__, i);
    eprintf("\t + key='%s' value='%s'\n", ptable->entries[i]->key.data,
            hexstring(ptable->entries[i]->value.data,
                      ptable->entries[i]->value.len));
    eprintf("\t + key len = %d\n\n", key_len);
    // print_entry(entry);
#endif

    // Insert pair into table
    HASH_ADD_KEYPTR(hh, table->entries, entry->key, key_len - 1, entry);

#ifdef DEBUG_STORE
    // eprintf("++\n");
#endif
  }

  // Load the table's version vector
  protobuf_unpack_vvec(&table->versions, ptable->versions);

  table__free_unpacked(ptable, NULL);
}

