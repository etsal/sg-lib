#include <assert.h>
#include <stdio.h>
#include <string.h> /* TODO: remove this after testing */

#include "kvcrdt.h"
#include "kvcrdt.pb-c.h"
#include "sg_common.h"
#ifdef __ENCLAVE__
#include "sg_stdfunc.h"
#endif

//#define DEBUG_KVCRDT 1

/*TODO: merge timestamps into vv */
static void print_pair(kvcrdt_pair_t *pair);

void
init_kvcrdt(kvcrdt_table_t *table, uint64_t uid)
{
	table->uid = uid;
	table->pairs = NULL;
	init_vvec(&table->versions, uid);
}

void
init_empty_kvcrdt(kvcrdt_table_t *table)
{
	table->uid = -1;
	table->pairs = NULL;
	table->versions = NULL;
}

int
is_empty_kvcrdt(kvcrdt_table_t *table)
{
	if (table->uid == -1 || table->pairs == NULL || table->versions == NULL)
		return 1;
	return 0;
}

int
find_kvcrdt(kvcrdt_table_t *table, uint64_t key, void *value, size_t value_len)
{
	kvcrdt_pair_t *pair = NULL;
	uint64_t ts;

	if (value_len > MAX_VALUE_LEN) {
		eprintf("Error, value length is greater than max expected %d actual %d\n",
		    MAX_VALUE_LEN, value_len);
		return 0;
	}

	if (table->pairs != NULL) {
		HASH_FIND_INT(table->pairs, &key, pair);
		if (pair == NULL) { // Element is already in the set, do nothing
			eprintf("Element does not exit!\n");
			return 0;
		}
		if (value_len < pair->value_len) {
			eprintf("Provided buffer is too small\n");
			return 0;
		}
		memcpy(value, pair->value, pair->value_len);
		return pair->value_len;
	}
	return 0;
}

int
add_kvcrdt(
    kvcrdt_table_t *table, uint64_t key, const void *value, size_t value_len)
{
	kvcrdt_pair_t *pair = NULL;
	uint64_t ts;

	assert(table->uid);

#ifdef DEBUG_KVCRDT
    eprintf("+ %s : start\n", __FUNCTION__);
    eprintf("+ %s : value = %s\n", __FUNCTION__, hexstring(value, value_len));
#endif

	if (value_len > MAX_VALUE_LEN) {
		eprintf("Error, value length is greater than max expected %d actual %d\n",
		    MAX_VALUE_LEN, value_len);
		return 0;
	}

	if (table->pairs != NULL) {
		HASH_FIND_INT(table->pairs, &key, pair);
		if (pair != NULL) { // Element is already in the set, do nothing
			eprintf("Element already exists\n");
			return 0;
		}
	}

	pair = malloc(sizeof(kvcrdt_pair_t));
	memset(pair, 0, sizeof(kvcrdt_pair_t));
	pair->key = key;
	pair->value_len = value_len;
	pair->value = malloc(value_len);
	memcpy(pair->value, value, value_len);
	pair->versions = NULL;

#ifdef DEBUG_KVCRDT
	eprintf("+ %s : Updating vvec\n", __FUNCTION__);
#endif
	// Increment timestamp for this
	update_vvec(&table->versions, table->uid);

#ifdef DEBUG_KVCRDT
	eprintf("+ %s : Adding version to element's ts array\n", __FUNCTION__);
#endif
	// Add version to element's ts array
	ts = get_vvec(&table->versions, table->uid);
	add_vvec(&pair->versions, table->uid, ts);

	// Add element to set
    HASH_ADD_INT(table->pairs, key, pair);

#ifdef DEBUG_KVCRDT 
    eprintf("+ %s : Done!\n", __FUNCTION__);
#endif
    return 1;
}

/*
 * Does not increment the local version vector for an insert
 */
void
add_pair_kvcrdt(kvcrdt_table_t *table, kvcrdt_pair_t *pair)
{
	kvcrdt_pair_t *new_pair = NULL;

	if (table->pairs != NULL) {
		HASH_FIND_INT(table->pairs, &pair->key, new_pair);
		if (new_pair != NULL)
			return;
	}

	assert(pair->value_len < MAX_VALUE_LEN);

	new_pair = malloc(sizeof(kvcrdt_pair_t));
	new_pair->key = pair->key;
	new_pair->value_len = pair->value_len;
	new_pair->value = malloc(pair->value_len);
	memcpy(new_pair->value, pair->value, pair->value_len);

	// Add version to element's ts array
	uint64_t ts = get_vvec(&table->versions, table->uid);

	// eprintf("Adding version vector (%d, %d)\n", table->uid, ts);
	add_vvec(&new_pair->versions, table->uid, ts);

	// Add element to set
	HASH_ADD_INT(table->pairs, key, new_pair);
}

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

void
free_kvcrdt(kvcrdt_table_t *table)
{
	kvcrdt_pair_t *pair = NULL, *tmp = NULL;
	if (!table)
		return;
	if (table->pairs) {
		HASH_ITER(hh, table->pairs, pair, tmp)
		{
			HASH_DEL(table->pairs, pair);
			free_vvec(&pair->versions);
			free(pair->value);
			free(pair);
		}
	}
	assert(table->pairs == NULL); // uthash should set this to NULL

	free_vvec(&table->versions);
}

void
merge_kvcrdt(kvcrdt_table_t *local_set, kvcrdt_table_t *remote_set)
{
	kvcrdt_pair_t *remote_pair, *local_pair, *next_pair;

	int do_remove, do_add = 0;

	// Remote removes
	HASH_ITER(hh, local_set->pairs, local_pair, next_pair)
	{

		remote_pair = NULL;

		HASH_FIND_INT(remote_set->pairs, &local_pair->key, remote_pair);

		if (remote_pair != NULL)
			continue; // Element exists in both sets

		// If the timestamps are equal or the remote_pair ts <
		// local_pair ts -> keep the element

		if (lt_vvec(&local_set->versions,
			&remote_set
			     ->versions)) { // Local add is older than remote
					    // remove/ne, remove wins
			do_remove = 1;
		} else if (cc_vvec(
			       &local_set->versions, &remote_set->versions)) {
			if (remote_set->uid >
			    local_set->uid) { // Break tie, higher uid wins
				do_remove = 1;
			}
		}

		if (do_remove) {
			HASH_DEL(local_set->pairs, local_pair);
			free_vvec(&local_pair->versions);
			free(local_pair);
			do_remove = 0;
		}
	}

	// Remote adds
	HASH_ITER(hh, remote_set->pairs, remote_pair, next_pair)
	{
		local_pair = NULL;
		HASH_FIND_INT(local_set->pairs, &remote_pair->key, local_pair);

		if (local_pair != NULL)
			continue;

		if (lt_vvec(&local_set->versions,
			&remote_pair->versions)) { // Local remove/ne is older
						   // than remote add, add wins
			do_add = 1;
		} else if (cc_vvec(&remote_pair->versions,
			       &local_set->versions)) { // Add wins
			if (remote_set->uid >
			    local_set->uid) { // Break tie, higher uid wins
				do_add = 1;
			}
		}

		if (do_add) {
			add_pair_kvcrdt(local_set, remote_pair);
			do_add = 0;
		}
	}

	// Merge version vectors
	merge_vvec(&local_set->versions, &remote_set->versions);
}

void
print_kvcrdt(kvcrdt_table_t *table)
{
	kvcrdt_pair_t *pair;
	eprintf("Table UID : %lu", table->uid);
	print_vvec(&table->versions);
	for (pair = table->pairs; pair != NULL; pair = pair->hh.next) {
		print_pair(pair);
		print_vvec(&pair->versions);
	}
}

void
print_fmt_kvcrdt(kvcrdt_table_t *table, void (*format)(const void *data))
{
	kvcrdt_pair_t *pair;
	edividerWithText("Table");
    eprintf("UID             : %lu\n", table->uid);
	print_vvec(&table->versions);
    edivider();
	for (pair = table->pairs; pair != NULL; pair = pair->hh.next) {
		eprintf("Key             : %lu\n", pair->key);
        eprintf("Version Vector  : ");
        print_vvec(&pair->versions);
        eprintf("Value           : \n"); 
		format(pair->value);
        edivider();
	}
}

static void
print_pair(kvcrdt_pair_t *pair)
{
    int print_len = (pair->value_len < 10) ? pair->value_len : 10;
    eprintf("<%lu, ", pair->key);
	eprintf("%s[...]> -> ", hexstring(pair->value, print_len));
}

void
serial_kvcrdt(kvcrdt_table_t *table, uint8_t **buf, size_t *len)
{
	KvcrdtTable ptable = KVCRDT_TABLE__INIT;
	ptable.uid = table->uid;
	ptable.n_pairs = HASH_COUNT(table->pairs);
	ptable.pairs = malloc(ptable.n_pairs * sizeof(KvcrdtPair *));

	int i = 0;
	for (kvcrdt_pair_t *p = table->pairs; p != NULL; p = p->hh.next) {

		ptable.pairs[i] = malloc(sizeof(KvcrdtPair));
		kvcrdt_pair__init(ptable.pairs[i]);

		// Handle key for kv-pair
		ptable.pairs[i]->key = p->key;

		// Handle value for kv-pair
		ptable.pairs[i]->value.len = p->value_len;
		ptable.pairs[i]->value.data = malloc(p->value_len);
		memcpy(ptable.pairs[i]->value.data, p->value, p->value_len);

		// Handle version vector for each kv-pair

		ptable.pairs[i]->versions = malloc(sizeof(VersionVector));
		version_vector__init(ptable.pairs[i]->versions);
		protobuf_pack_vvec(&p->versions, ptable.pairs[i]->versions);

		++i;
	}

	// Handle version vector for table
	ptable.versions = malloc(sizeof(VersionVector));
	version_vector__init(ptable.versions);
	protobuf_pack_vvec(&table->versions, ptable.versions);

	*len = kvcrdt_table__get_packed_size(&ptable);
	*buf = malloc(*len);

	kvcrdt_table__pack(&ptable, *buf);

	// Free each pair
	for (i = 0; i < ptable.n_pairs; ++i) {
		protobuf_free_packed_vvec(ptable.pairs[i]->versions);
		free(ptable.pairs[i]->versions);
		free(ptable.pairs[i]->value.data);
		free(ptable.pairs[i]);
	}
	free(ptable.pairs);

	// Free tbale version vector
	protobuf_free_packed_vvec(ptable.versions);
	free(ptable.versions);
	return;
}

void
deserial_kvcrdt(kvcrdt_table_t *table, uint8_t *buf, size_t len)
{
	KvcrdtTable *ptable = NULL;

	assert(table);

	ptable = kvcrdt_table__unpack(NULL, len, buf);
	if (!ptable) {
		return;
	}

	free_kvcrdt(table);
	table->uid = ptable->uid;
	for (int i = 0; i < ptable->n_pairs; ++i) {
		// Create pair
		kvcrdt_pair_t *pair = malloc(sizeof(kvcrdt_pair_t));
		pair->key = ptable->pairs[i]->key;
		pair->value_len = ptable->pairs[i]->value.len;
		pair->value = malloc(pair->value_len);
		memcpy(
		    pair->value, ptable->pairs[i]->value.data, pair->value_len);
		pair->versions = NULL;
		protobuf_unpack_vvec(
		    &pair->versions, ptable->pairs[i]->versions);

		// Insert pair into table
		HASH_ADD_INT(table->pairs, key, pair);
	}

	// Load the table's version vector
	protobuf_unpack_vvec(&table->versions, ptable->versions);

	kvcrdt_table__free_unpacked(ptable, NULL);
}
