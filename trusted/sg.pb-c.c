/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: sg.proto */

/* Do not generate deprecated warnings for self */
#ifndef PROTOBUF_C__NO_DEPRECATED
#define PROTOBUF_C__NO_DEPRECATED
#endif

#include "sg.pb-c.h"
void   state_sg__init
                     (StateSg         *message)
{
  static const StateSg init_value = STATE_SG__INIT;
  *message = init_value;
}
size_t state_sg__get_packed_size
                     (const StateSg *message)
{
  assert(message->base.descriptor == &state_sg__descriptor);
  return protobuf_c_message_get_packed_size ((const ProtobufCMessage*)(message));
}
size_t state_sg__pack
                     (const StateSg *message,
                      uint8_t       *out)
{
  assert(message->base.descriptor == &state_sg__descriptor);
  return protobuf_c_message_pack ((const ProtobufCMessage*)message, out);
}
size_t state_sg__pack_to_buffer
                     (const StateSg *message,
                      ProtobufCBuffer *buffer)
{
  assert(message->base.descriptor == &state_sg__descriptor);
  return protobuf_c_message_pack_to_buffer ((const ProtobufCMessage*)message, buffer);
}
StateSg *
       state_sg__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data)
{
  return (StateSg *)
     protobuf_c_message_unpack (&state_sg__descriptor,
                                allocator, len, data);
}
void   state_sg__free_unpacked
                     (StateSg *message,
                      ProtobufCAllocator *allocator)
{
  if(!message)
    return;
  assert(message->base.descriptor == &state_sg__descriptor);
  protobuf_c_message_free_unpacked ((ProtobufCMessage*)message, allocator);
}
static const ProtobufCFieldDescriptor state_sg__field_descriptors[2] =
{
  {
    "kc",
    1,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(StateSg, kc),
    &keycert__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
  {
    "t",
    2,
    PROTOBUF_C_LABEL_REQUIRED,
    PROTOBUF_C_TYPE_MESSAGE,
    0,   /* quantifier_offset */
    offsetof(StateSg, t),
    &table__descriptor,
    NULL,
    0,             /* flags */
    0,NULL,NULL    /* reserved1,reserved2, etc */
  },
};
static const unsigned state_sg__field_indices_by_name[] = {
  0,   /* field[0] = kc */
  1,   /* field[1] = t */
};
static const ProtobufCIntRange state_sg__number_ranges[1 + 1] =
{
  { 1, 0 },
  { 0, 2 }
};
const ProtobufCMessageDescriptor state_sg__descriptor =
{
  PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
  "stateSg",
  "StateSg",
  "StateSg",
  "",
  sizeof(StateSg),
  2,
  state_sg__field_descriptors,
  state_sg__field_indices_by_name,
  1,  state_sg__number_ranges,
  (ProtobufCMessageInit) state_sg__init,
  NULL,NULL,NULL    /* reserved[123] */
};
