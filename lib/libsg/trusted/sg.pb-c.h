/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: sg.proto */

#ifndef PROTOBUF_C_sg_2eproto__INCLUDED
#define PROTOBUF_C_sg_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003003 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

#include "store.pb-c.h"
#include "keycert.pb-c.h"

typedef struct _StateSg StateSg;


/* --- enums --- */


/* --- messages --- */

struct  _StateSg
{
  ProtobufCMessage base;
  Keycert *kc;
  Table *t;
};
#define STATE_SG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&state_sg__descriptor) \
    , NULL, NULL }


/* StateSg methods */
void   state_sg__init
                     (StateSg         *message);
size_t state_sg__get_packed_size
                     (const StateSg   *message);
size_t state_sg__pack
                     (const StateSg   *message,
                      uint8_t             *out);
size_t state_sg__pack_to_buffer
                     (const StateSg   *message,
                      ProtobufCBuffer     *buffer);
StateSg *
       state_sg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   state_sg__free_unpacked
                     (StateSg *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*StateSg_Closure)
                 (const StateSg *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor state_sg__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_sg_2eproto__INCLUDED */