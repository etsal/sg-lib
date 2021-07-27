#include <stdio.h>

#include "sg_common.h"
#include "vvec.h"

#if __ENCLAVE__
#include "sg_stdfunc.h"
#endif

/*
 * @param vv
 * @param uid
 *
 * Initialize the ts at uid to 0.
 */
void init_vvec(vvec_t *vv, uint64_t uid) {
  *vv = NULL;
  add_vvec(vv, uid, 0);
}

/*
 * @param vv1
 * @param vv2
 * @return 1 if vv1 < vv2, 0 otherwise
 *
 * vv1 < vv2 IFF every element in vv1 < / = to every elemet in vv2 AND at
 * least one element in vv1 is STRICTLY less than the corresponding element in
 * vv2
 */
int lt_vvec(vvec_t *vv1, vvec_t *vv2) {
  version_t *v1, *v2 = NULL;

  if (vv1 == NULL || vv2 == NULL)
    return 0;

  for (v2 = (*vv2); v2 != NULL; v2 = v2->hh.next) {
    v1 = NULL;
    HASH_FIND_INT(*vv1, &v2->uid, v1);
    if (v1 == NULL)
      continue; // vv2 contains a versions that vv1 has not seen before
    if (!(v1->ts < v2->ts))
      return 0;
  }

  for (v1 = (*vv1); v1 != NULL; v1 = v1->hh.next) {
    v2 = NULL;
    HASH_FIND_INT(*vv2, &v1->uid, v2);
    if (v2 == NULL) {
      if (v1->ts == 0)
        continue;
      return 0;
    }
  }
  return 1;
}

int eq_vvec(vvec_t *vv1, vvec_t *vv2) {
  version_t *v1, *v2 = NULL;

  if (vv1 == NULL || vv2 == NULL)
    return 0;

  for (v1 = (*vv1); v1 != NULL; v1 = v1->hh.next) {
    v2 = NULL;
    HASH_FIND_INT(*vv2, &v1->uid, v2);
    if (v2 == NULL) {
      if (v1->ts == 0)
        continue; // Both timestamps are zero
      return 0;   // Timestamps differ
    }
    if (!(v1->ts == v2->ts))
      return 0;
  }
  return 1;
}

/*
 * TODO: This can be more efficient
 * @param vv1
 * @param vv2
 * @return 1 if vv1 || vv2, 0 otherwise
 */
int cc_vvec(vvec_t *vv1, vvec_t *vv2) {
  if ((!lt_vvec(vv1, vv2) || !lt_vvec(vv2, vv1)) || !eq_vvec(vv1, vv2)) {
    return 1;
  }

  return 0;
}

/*
 * @param vv
 * @param uid
 * @param ts
 *
 * @retrun 1 on successful add, 0 otherwise
 *
 * If ts is NULL, then version's timestamp (ts) will be initialized to 0
 * otherwise, we set to ts
 */
int add_vvec(vvec_t *vv, uint64_t uid, uint64_t ts) {
  version_t *new_version = NULL;

    if (vv) { // There are no known versions
        HASH_FIND_INT(*vv, &uid, new_version);
        if (new_version) {
            eprintf("Error, version with uid %lu already exists.\n", uid);
            return 0;
        }
    }
  new_version = malloc(sizeof(version_t)); // Each version inserted is malloc'd
  new_version->uid = uid;
  new_version->ts = ts;
  HASH_ADD_INT(*vv, uid, new_version);
  return 1;
}

/*
 * Return the ts of the version vector vv for the given uid.
 *
 * @param vv
 * @param uid
 */
uint64_t get_vvec(vvec_t *vv, uint64_t uid) {
  version_t *version = NULL;
  if (!(*vv))
    return 0;
  HASH_FIND_INT(*vv, &uid, version);
  if (!version)
    return 0;
  return version->ts;
}

void set_vvec(vvec_t *vv, uint64_t uid, uint64_t ts) {
  version_t *version = NULL;
  if (*vv)
    HASH_FIND_INT(*vv, &uid, version);
  version->ts = ts;
}

/*
 * Find the version with the provided uid and increment the ts by one
 *
 * @param vv
 * @param uid
 * @param ts
 */
void update_vvec(vvec_t *vv, uint64_t uid) {
  version_t *version = NULL;
  if (*vv)
    HASH_FIND_INT(*vv, &uid, version);
  if (version == NULL)
    return;
  ++version->ts;
}

/*
 * Copy vv2 to vv1, new memory allocated.
 *
 * @param vv1
 * @param vv2
 */
void copy_vvec(vvec_t *vv1, vvec_t *vv2) {
  version_t *v2 = NULL;
  if (*vv1)
    free_vvec(vv1);
  for (v2 = (*vv2); v2 != NULL; v2 = v2->hh.next)
    add_vvec(vv1, v2->uid,
             v2->ts); // TODO: can speed this up with an "unsafe" add
}

/*
 * Merge remote into local.
 *
 * @param local
 * @param remote
 */
void merge_vvec(vvec_t *local, vvec_t *remote) {
  version_t *l, *r, *new_v;
  // Loop through remote versions
  for (r = (*remote); r != NULL; r = r->hh.next) {
    l = NULL;
    if (*local)
      HASH_FIND_INT(*local, &r->uid, l);
    if (!l) {
      add_vvec(local, r->uid, r->ts);
      continue;
    }
    eprintf("+++ Taking max(%d, %d)\n", l->ts, r->ts);
    l->ts = max(l->ts, r->ts);
  }
}

void free_vvec(vvec_t *vv) {
  version_t *v, *tmp;
  if (!(*vv))
    return;
  HASH_ITER(hh, *vv, v, tmp) {
    HASH_DEL(*vv, v);
    free(v);
  }
  assert(*vv == NULL);
}

void print_vvec(vvec_t *vv) {
  version_t *v;
  if (!(*vv)) {
    eprintf("(empty)\n");
    return;
  }

  for (v = (*vv); v != NULL; v = v->hh.next)
    eprintf("(uid: %d, ts: %d) ", v->uid, v->ts);

  eprintf("\n");
}

void protobuf_pack_vvec(vvec_t *vv, VersionVector *pvv) {

  pvv->n_versions = HASH_COUNT(*vv);
  pvv->versions = malloc(pvv->n_versions * sizeof(Version *));

  int i = 0;
  for (version_t *v = (*vv); v != NULL; v = v->hh.next) {
    pvv->versions[i] = malloc(sizeof(Version));
    version__init(pvv->versions[i]);
    pvv->versions[i]->uid = v->uid;
    pvv->versions[i]->ts = v->ts;
    i++;
  }
}

void protobuf_free_packed_vvec(VersionVector *pvv) {
  for (int i = 0; i < pvv->n_versions; ++i)
    free(pvv->versions[i]);
  free(pvv->versions);
}

void protobuf_unpack_vvec(vvec_t *vv, VersionVector *pvv) {
  uint64_t uid = 0, ts = 0;

  assert(!(*vv) && pvv); // Make sure vv is null and pvv is non null

  for (int i = 0; i < pvv->n_versions; ++i) {
    uid = pvv->versions[i]->uid;
    ts = pvv->versions[i]->ts;
    add_vvec(vv, uid, ts);
  }
}

void serial_vvec(vvec_t *vv, uint8_t **buf, size_t *len) {
  VersionVector proto_version_vec = VERSION_VECTOR__INIT;
  proto_version_vec.n_versions = HASH_COUNT(*vv);
  proto_version_vec.versions =
      malloc(proto_version_vec.n_versions * sizeof(Version *));

  // eprintf("Packing: Found %lu versions.\n", proto_version_vec.n_versions);

  // Construct protobuf structs
  int i = 0;
  for (version_t *v = (*vv); v != NULL; v = v->hh.next) {
    proto_version_vec.versions[i] = malloc(sizeof(Version));
    version__init(proto_version_vec.versions[i]);
    proto_version_vec.versions[i]->uid = v->uid;
    proto_version_vec.versions[i]->ts = v->ts;
    ++i;
  }

  // Generate serialized vvec
  *len = version_vector__get_packed_size(&proto_version_vec);
  *buf = malloc(*len);
  version_vector__pack(&proto_version_vec, *buf);

  // Free protobuf structs
  for (i = 0; i < proto_version_vec.n_versions; ++i)
    free(proto_version_vec.versions[i]);
  free(proto_version_vec.versions);
}

void deserial_vvec(vvec_t *vv, uint8_t *buf, size_t len) {
  VersionVector *proto_version_vec = NULL;
  uint64_t uid, ts = 0;

  free_vvec(vv);
  proto_version_vec = version_vector__unpack(NULL, len, buf);

  if (!proto_version_vec) {
    eprintf("Error, version_vector__unpack\n");
    return;
  }

  // eprintf("Unpacking: Found %lu versions.\n", proto_version_vec->n_versions);

  for (int i = 0; i < proto_version_vec->n_versions; ++i) {
    uid = proto_version_vec->versions[i]->uid;
    ts = proto_version_vec->versions[i]->ts;
    add_vvec(vv, uid, ts);
  }

  version_vector__free_unpacked(proto_version_vec, NULL);
}
