
#include "sg_messages.h"
#include "sg_common.h"
#include "sg_stdfunc.h" //htonl
#include <string.h>     // memcpy

#define DEBUG_SG 1

static const char *get_message_header_type(int type) {
  switch (type) {
  case HEARTBEAT:
    return "HEARTBEAT";
  case INCOMING:
    return "INCOMING";
  case MESSAGE:
    return "MESSAGE";
  default:
    return "UNKNOWN";
  }
}

/*
 * @param incoming_len Optional, this will populate the incoming_len field of
 * message_header
 */
static void prepare_frame(int type, uint8_t *data, size_t data_len,
                          uint8_t **out, size_t *out_len) {

  uint32_t incoming_len = htonl(data_len);
  struct message_header header;

  header.type = type;
  header.incoming_len = 0;
  *out_len = 0;

  switch (type) {
  case HEARTBEAT:
    *out = malloc(sizeof(struct message_header));
    memcpy(*out, &header, sizeof(header));
    *out_len += sizeof(header);
    break;

  case INCOMING: // always sizeof(struct message_header)
    header.incoming_len = data_len;
    *out = malloc(sizeof(struct message_header));
    memcpy(*out, &header, sizeof(header));
    *out_len += sizeof(header);
    break;

  case MESSAGE: // always data_len + sizeof(message_header)
    *out = malloc(sizeof(struct message_header) + data_len);
    memcpy(*out, &header, sizeof(header));
    *out_len += sizeof(header);
    memcpy(*out + sizeof(header), data, data_len);
    *out_len += data_len;
    break;
  default:
    break;
  }

#ifdef DEBUG_SG
  eprintf("\t\t+ (%s) Prepared %s frame '%s'\n", __FUNCTION__,
          get_message_header_type(header.type), hexstring(*out, *out_len));
#endif
}

/*
 * Sends an incoming message and the message itself
 */
int prepare_and_send_updates(ratls_ctx_t *ctx, uint8_t *data, size_t data_len) {

  uint8_t *out;
  size_t out_len;
  int ret;

#ifdef DEBUG_SG
  eprintf("+ (%s) start\n", __FUNCTION__);
#endif

  prepare_frame(INCOMING, NULL, data_len, &out, &out_len);
  ret = write_ratls(ctx, out, out_len);
  free(out);
  
  if (ret != out_len)
    return 1;

  prepare_frame(MESSAGE, data, data_len, &out, &out_len);

  ret = write_ratls(ctx, out, out_len);
  free(out);

  if (ret != out_len)
    return 1;

  return 0;
}

/* process_message
 * Reads the message from (ctx is a server_connections)
 */
int receive_message(ratls_ctx_t *ctx, int *type, uint8_t **buf, size_t *buf_len) {

  struct message_header header;
  //uint8_t *mbuf;
  //int mbuf_len;
  size_t incoming_length;
  int ret, len;


  *buf_len = 0;

  ret = read_ratls(ctx, (uint8_t *)&header, sizeof(struct message_header));

  if (ret == 0) {
#ifdef DEBUG_SG
    eprintf("\t+ (%s) ERROR: Connection closed\n", __FUNCTION__);
#endif
    exit(1);
    // return 1;
  }
  if (ret != sizeof(struct message_header)) {
#ifdef DEBUG_SG
    eprintf("\t\t+ (%s) FAILED: Read %d instead of %d \n", __FUNCTION__, ret,
            sizeof(struct message_header));
#endif
    return 1;
  }

  switch (header.type) {
  case HEARTBEAT:
#ifdef DEBUG_SG
    eprintf("I don't know how to handle HEARTBEAT\n");
#endif
    exit(1);
  case INCOMING:
#ifdef DEBUG_SG
//    eprintf("\t+ (%s) Expecting message of size %d\n", __FUNCTION__,
//            header.incoming_len);
#endif
    len = sizeof(struct message_header) + header.incoming_len;
    *buf = malloc(len + 1);
    ret = read_ratls(ctx, *buf, len);
    *buf_len = ret;
    *type = INCOMING;
  
    *buf = *buf + sizeof(header);
    *buf_len = *buf_len - sizeof(header);

    if (ret != len) {
#ifdef DEBUG_SG
      eprintf("\t\t+ (%s) FAILED: to read message\n", __FUNCTION__);
#endif
      return 1;
    }
    break;

  default:
#ifdef DEBUG_SG
    eprintf("I don't know how to handle MESSAGE\n");
#endif
  }

  return 0;
}

