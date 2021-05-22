#ifndef __VERSION_VEC_H__
#define __VERSION_VEC_H__

#include "uthash/src/uthash.h"
#include "vvec.pb-c.h"

#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

typedef struct version_ {
  uint64_t uid;
  uint64_t ts;
  UT_hash_handle hh;
} version_t;

/*
typedef struct vvec_ {
        version_t *versions;
} vvec_t;
*/

typedef version_t *vvec_t;

/* Standard version vector functions */
void init_vvec(vvec_t *vv, uint64_t uid);
int add_vvec(vvec_t *vv, uint64_t uid, uint64_t ts);
void set_vvec(vvec_t *vv, uint64_t uid, uint64_t ts);
uint64_t get_vvec(vvec_t *vv, uint64_t uid);
void update_vvec(vvec_t *vv, uint64_t uid); /* Increment ts by one */
void copy_vvec(vvec_t *vv1, vvec_t *vv2);

/* Comparison functions */
int lt_vvec(vvec_t *vv1, vvec_t *vv2);
int eq_vvec(vvec_t *vv1, vvec_t *vv2);
int cc_vvec(vvec_t *vv1, vvec_t *vv2);
void merge_vvec(vvec_t *local, vvec_t *remote);

/* Serialization function */
void serial_vvec(vvec_t *vv, uint8_t **buf, size_t *len);
void deserial_vvec(vvec_t *vv, uint8_t *buf, size_t len);
void protobuf_pack_vvec(vvec_t *vv, VersionVector *pvv);
void protobuf_free_packed_vvec(VersionVector *pvv);
void protobuf_unpack_vvec(vvec_t *vv, VersionVector *pvv);

/* Debug functions */
void free_vvec(vvec_t *vv);
void print_vvec(vvec_t *vv);

#endif
