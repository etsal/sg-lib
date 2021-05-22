/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: key.proto */

#ifndef PROTOBUF_C_key_2eproto__INCLUDED
#define PROTOBUF_C_key_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif

typedef struct _Key Key;

/* --- enums --- */

/* --- messages --- */

struct _Key {
	ProtobufCMessage base;
	int32_t type;
	int32_t curve;
	size_t n_kbuf;
	int32_t *kbuf;
};
#define KEY__INIT                                         \
	{                                                 \
		PROTOBUF_C_MESSAGE_INIT(&key__descriptor) \
		, 0, 0, 0, NULL                           \
	}

/* Key methods */
void key__init(Key *message);
size_t key__get_packed_size(const Key *message);
size_t key__pack(const Key *message, uint8_t *out);
size_t key__pack_to_buffer(const Key *message, ProtobufCBuffer *buffer);
Key *key__unpack(
    ProtobufCAllocator *allocator, size_t len, const uint8_t *data);
void key__free_unpacked(Key *message, ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Key_Closure)(const Key *message, void *closure_data);

/* --- services --- */

/* --- descriptors --- */

extern const ProtobufCMessageDescriptor key__descriptor;

PROTOBUF_C__END_DECLS

#endif /* PROTOBUF_C_key_2eproto__INCLUDED */