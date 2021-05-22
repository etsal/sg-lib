/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: store.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "store.pb-c.h"
void   entry__init
                     (Entry         *message)
{
  static const Entry init_value = ENTRY__INIT;
  *message = init_value;
}
size_t entry__get_packed_size
                     (const Entry *message)
{
  assert(message->base.descriptor == &entry__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t entry__pack
                     (const Entry *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &entry__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t entry__pack_to_buffer
                     (const Entry *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &entry__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Entry *
       entry__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Entry *)
     protobuf_c_message_unpack (&entry__descriptor,
                                allocator, len, data);
}
void   entry__free_unpacked
                     (Entry *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &entry__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   table__init
                     (Table         *message)
{
  static const Table init_value = TABLE__INIT;
  *message = init_value;
}
size_t table__get_packed_size
                     (const Table *message)
{
  assert(message->base.descriptor == &table__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t table__pack
                     (const Table *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &table__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t table__pack_to_buffer
                     (const Table *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &table__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Table *
       table__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Table *)
     protobuf_c_message_unpack (&table__descriptor,
                                allocator, len, data);
}
void   table__free_unpacked
                     (Table *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &table__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor entry__field_descriptors[3] =
{
  {
    "key",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Entry, key),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "value",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_BYTES,
    0,   /* quantifier_offset */
    offsetof(Entry, value),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "versions",
    4,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Entry, versions),
    &version_vector__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned entry__field_indices_by_name[] = {
  0,   /* field[0] = key */
  1,   /* field[1] = value */
  2,   /* field[2] = versions */
};
static const ProtobufCIntRange entry__number_ranges[2 + 1] =
{
  { 1, 0 },
  { 4, 2 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor entry__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "entry",
  "Entry",
  "Entry",
  "",
  sizeof(Entry),
  3,
  entry__field_descriptors,
  entry__field_indices_by_name,
  2,  entry__number_ranges,
  (ProtobufCMessageInit) entry__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor table__field_descriptors[3] =
{
  {
    "uid",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_UINT64,
    0,   /* quantifier_offset */
    offsetof(Table, uid),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "entries",
    2,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_MESSAGE,
    offsetof(Table, n_entries),
    offsetof(Table, entries),
    &entry__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "versions",
    3,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(Table, versions),
    &version_vector__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned table__field_indices_by_name[] = {
  1,   /* field[1] = entries */
  0,   /* field[0] = uid */
  2,   /* field[2] = versions */
};
static const ProtobufCIntRange table__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 3 }
};
const ProtobufCMessageDescriptor table__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "table",
  "Table",
  "Table",
  "",
  sizeof(Table),
  3,
  table__field_descriptors,
  table__field_indices_by_name,
  1,  table__number_ranges,
  (ProtobufCMessageInit) table__init,
  NULL,NULL,NULL    /* reserved[123] */
};
