/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: vvec.proto */

#ifndef PROTOBUF_C_vvec_2eproto__INCLUDED
#define PROTOBUF_C_vvec_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

typedef struct _Version Version;
typedef struct _VersionVector VersionVector;

/* --- enums --- */

/* --- messages --- */

struct _Version {
  ProtobufCMessage base;
  uint64_t uid;
  uint64_t ts;
};
#define VERSION__INIT                                                          \
  {                                                                            \
    PROTOBUF_C_MESSAGE_INIT(&version__descriptor)                              \
    , 0, 0                                                                     \
  }

struct _VersionVector {
  ProtobufCMessage base;
  size_t n_versions;
  Version **versions;
};
#define VERSION_VECTOR__INIT                                                   \
  {                                                                            \
    PROTOBUF_C_MESSAGE_INIT(&version_vector__descriptor)                       \
    , 0, NULL                                                                  \
  }

/* Version methods */
void version__init(Version *message);
size_t version__get_packed_size(const Version *message);
size_t version__pack(const Version *message, uint8_t *out);
size_t version__pack_to_buffer(const Version *message, ProtobufCBuffer *buffer);
Version *version__unpack(ProtobufCAllocator *allocator, size_t len,
                         const uint8_t *data);
void version__free_unpacked(Version *message, ProtobufCAllocator *allocator);
/* VersionVector methods */
void version_vector__init(VersionVector *message);
size_t version_vector__get_packed_size(const VersionVector *message);
size_t version_vector__pack(const VersionVector *message, uint8_t *out);
size_t version_vector__pack_to_buffer(const VersionVector *message,
                                      ProtobufCBuffer *buffer);
VersionVector *version_vector__unpack(ProtobufCAllocator *allocator, size_t len,
                                      const uint8_t *data);
void version_vector__free_unpacked(VersionVector *message,
                                   ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Version_Closure)(const Version *message, void *closure_data);
typedef void (*VersionVector_Closure)(const VersionVector *message,
                                      void *closure_data);

/* --- services --- */

/* --- descriptors --- */

extern const ProtobufCMessageDescriptor version__descriptor;
extern const ProtobufCMessageDescriptor version_vector__descriptor;

PROTOBUF_C__END_DECLS

#endif /* PROTOBUF_C_vvec_2eproto__INCLUDED */
