/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: keycert.proto */

#ifndef PROTOBUF_C_keycert_2eproto__INCLUDED
#define PROTOBUF_C_keycert_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _Keycert Keycert;


/* --- enums --- */


/* --- messages --- */

struct  _Keycert
{
  ProtobufCMessage base;
  uint32_t key_type;
  ProtobufCBinaryData key;
  ProtobufCBinaryData cert;
};
#define KEYCERT__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&keycert__descriptor) \
    , 0, {0,NULL}, {0,NULL} }


/* Keycert methods */
void   keycert__init
                     (Keycert         *message);
size_t keycert__get_packed_size
                     (const Keycert   *message);
size_t keycert__pack
                     (const Keycert   *message,
                      uint8_t             *out);
size_t keycert__pack_to_buffer
                     (const Keycert   *message,
                      ProtobufCBuffer     *buffer);
Keycert *
       keycert__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   keycert__free_unpacked
                     (Keycert *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Keycert_Closure)
                 (const Keycert *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor keycert__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_keycert_2eproto__INCLUDED */