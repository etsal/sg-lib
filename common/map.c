#include <assert.h>
#include <string.h>

#include "map.h"
#include "map.pb-c.h"
#include "sg_common.h"
#include "xmem.h"
/*
#ifdef __ENCLAVE__
#include "stdfunc.h"
#endif
*/
void
free_strmap(strmap_t *map)
{
	strmap_entry_t *entry, *tmp = NULL;

	if (*map == NULL)
		return;

	HASH_ITER(hh, *map, entry, tmp)
	{
		HASH_DEL(*map, entry);
		xfree(entry);
	}
	*map = NULL;
}

int
insert_strmap(strmap_t *map, const char *str1, const char *str2)
{
	assert(strlen(str1) < STRMAP_MAX_ELEM_LEN);
	assert(strlen(str2) < STRMAP_MAX_ELEM_LEN);

	strmap_entry_t *entry = NULL;

	if (*map != NULL) {
		HASH_FIND_STR(*map, str1, entry);
		if (entry != NULL)
			return 0;
	}
	entry = xmalloc(sizeof(strmap_entry_t));
	strcpy(entry->first, str1);
	strcpy(entry->second, str2);
	eprintf("new entry (%s,%s)\n", entry->first, entry->second);
	HASH_ADD_STR(*map, first, entry);
	return 1;
}

const char *
find_strmap(strmap_t map, const char *first)
{
	strmap_entry_t *entry = NULL;
	if (map == NULL)
		return NULL;
	HASH_FIND_STR(map, first, entry);
	if (entry)
		return entry->second;
	return NULL;
}

size_t
len_strmap(strmap_t map)
{
	strmap_entry_t *entry;
	size_t count = 0;

	for (entry = map; entry != NULL; entry = entry->hh.next) {
		count++;
	}
	return count;
}

void
eprint_strmap(strmap_t map)
{
	strmap_entry_t *entry;
	if (map == NULL)
		eprintf("No elements\n");
	for (entry = map; entry != NULL; entry = entry->hh.next) {
		eprintf("(%s, %s)\n", entry->first, entry->second);
	}
	eprintf("\n");
}

void
serialize_strmap(strmap_t map, uint8_t **buf, size_t *len)
{
	StrmapProto pmap = STRMAP_PROTO__INIT;
	StrmapEntryProto **pmap_entries;
	size_t pmap_len = len_strmap(map);

	pmap_entries = xmalloc(sizeof(StrmapEntryProto *) * pmap_len);

	int i = 0;
	strmap_entry_t *entry = NULL;

	for (entry = map; entry != NULL; entry = entry->hh.next) {
		eprintf("serializing %d\n", i + 1);
		pmap_entries[i] = xmalloc(sizeof(StrmapEntryProto));
		eprintf("after xmalloc\n");
		strmap_entry_proto__init(pmap_entries[i]);
		eprintf("after proto init\n");
		pmap_entries[i]->first = xmalloc(STRMAP_MAX_ELEM_LEN);
		pmap_entries[i]->second = xmalloc(STRMAP_MAX_ELEM_LEN);
		strcpy(pmap_entries[i]->first, entry->first);
		strcpy(pmap_entries[i]->second, entry->second);
		eprintf("(%s, %s)\n", pmap_entries[i]->first,
		    pmap_entries[i]->second);
		i++;
	}
	pmap.n_entries = pmap_len;
	pmap.entries = pmap_entries;

	*len = strmap_proto__get_packed_size(&pmap);
	*buf = xmalloc(*len);

	strmap_proto__pack(&pmap, *buf);

	eprintf("serialized data: %s\n", hexstring(*buf, *len));
	for (i = 0; i < pmap_len; ++i) {
		xfree(pmap_entries[i]->first);
		xfree(pmap_entries[i]->second);
		xfree(pmap_entries[i]);
	}
	xfree(pmap_entries);
}

void
deserialize_strmap(strmap_t *map, uint8_t *buf, size_t len)
{
	StrmapProto *pmap = strmap_proto__unpack(NULL, len, buf);

	free_strmap(map);
	if (pmap == NULL)
		return;

	for (int i = 0; i < pmap->n_entries; ++i) {
		insert_strmap(
		    map, pmap->entries[i]->first, pmap->entries[i]->second);
	}

	strmap_proto__free_unpacked(pmap, NULL);
}
