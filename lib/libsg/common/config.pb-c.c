/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: config.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "config.pb-c.h"
void   host__init
                     (Host         *message)
{
  static const Host init_value = HOST__INIT;
  *message = init_value;
}
size_t host__get_packed_size
                     (const Host *message)
{
  assert(message->base.descriptor == &host__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t host__pack
                     (const Host *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &host__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t host__pack_to_buffer
                     (const Host *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &host__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Host *
       host__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Host *)
     protobuf_c_message_unpack (&host__descriptor,
                                allocator, len, data);
}
void   host__free_unpacked
                     (Host *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &host__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
void   config__init
                     (Config         *message)
{
  static const Config init_value = CONFIG__INIT;
  *message = init_value;
}
size_t config__get_packed_size
                     (const Config *message)
{
  assert(message->base.descriptor == &config__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t config__pack
                     (const Config *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &config__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t config__pack_to_buffer
                     (const Config *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &config__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
Config *
       config__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (Config *)
     protobuf_c_message_unpack (&config__descriptor,
                                allocator, len, data);
}
void   config__free_unpacked
                     (Config *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &config__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor host__field_descriptors[1] =
{
  {
    "host",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Host, host),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned host__field_indices_by_name[] = {
  0,   /* field[0] = host */
};
static const ProtobufCIntRange host__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 1 }
};
const ProtobufCMessageDescriptor host__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "host",
  "Host",
  "Host",
  "",
  sizeof(Host),
  1,
  host__field_descriptors,
  host__field_indices_by_name,
  1,  host__number_ranges,
  (ProtobufCMessageInit) host__init,
  NULL,NULL,NULL    /* reserved[123] */
};
static const ProtobufCFieldDescriptor config__field_descriptors[2] =
{
  {
    "database_file",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_STRING,
    0,   /* quantifier_offset */
    offsetof(Config, database_file),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "hosts",
    2,
    PROTOBUF_C_LABEL_REPEATED,
    PROTOBUF_C_TYPE_STRING,
    offsetof(Config, n_hosts),
    offsetof(Config, hosts),
    NULL,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned config__field_indices_by_name[] = {
  0,   /* field[0] = database_file */
  1,   /* field[1] = hosts */
};
static const ProtobufCIntRange config__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor config__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "config",
  "Config",
  "Config",
  "",
  sizeof(Config),
  2,
  config__field_descriptors,
  config__field_indices_by_name,
  1,  config__number_ranges,
  (ProtobufCMessageInit) config__init,
  NULL,NULL,NULL    /* reserved[123] */
};
