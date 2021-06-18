
#include <string.h>     // memcpy
#include "sg_messages.h"
#include "sg_stdfunc.h" //htonl
#include "sg_common.h"

#define DEBUG_SG 1

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

  case INCOMING:
    header.incoming_len = data_len;
    *out = malloc(sizeof(struct message_header));
    memcpy(*out, &header, sizeof(header));
    *out_len += sizeof(header);
//eprintf("PREPARED INCOMING FRAME %s\n", hexstring(*out, *out_len));
    break;

  case MESSAGE:

    *out = malloc(sizeof(struct message_header) + data_len);
    memcpy(*out, &header, sizeof(header));
    *out_len += sizeof(header);
    memcpy(*out + sizeof(header), data, data_len);
    *out_len += data_len;
//eprintf("PREPARED MESSAGE FRAME %s\n", hexstring(*out, *out_len));
    break;

  default:
    break;
  }
}

/*
 * Sends an incoming message and the message itself
 */
int prepare_and_send_updates(ratls_ctx_t *ctx, uint8_t *data, size_t data_len) {

  uint8_t *out;
  size_t out_len;
  int ret;

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
int process_message(ratls_ctx_t *ctx) {

  struct message_header header;
  uint8_t *buf;
  int buf_len;
  size_t incoming_length;
  int ret;

  ret = read_ratls(ctx, (uint8_t *)&header, sizeof(struct message_header));

  if (ret == 0) {
#ifdef DEBUG_SG
    eprintf("\t+ (%s) WARNING: Connection closed\n", __FUNCTION__);
#endif
    return 1;
  }
  if (ret != sizeof(struct message_header)) {
#ifdef DEBUG_SG
    eprintf("\t+ (%s) FAILED: Read %d instead of %d \n", __FUNCTION__, ret, sizeof(struct message_header));
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
    eprintf("\t+ (%s) Expecting message of size %d\n", __FUNCTION__,
            header.incoming_len);
#endif
    buf_len = sizeof(struct message_header) + header.incoming_len;
    buf = malloc(buf_len + 1);
    ret = read_ratls(ctx, buf, buf_len);
    if (ret != buf_len) {
#ifdef DEBUG_SG
      eprintf("\t+ (%s) FAILED: to read message\n", __FUNCTION__);
#endif
      return 1;
    }
#ifdef DEBUG_SG
    eprintf("\t+ (%s) SUCCESS: read message -->%s<--\n", __FUNCTION__, buf + sizeof(struct message_header));//hexstring(buf, buf_len));
#endif
    break;

  default:
#ifdef DEBUG_SG
    eprintf("I don't know how to handle MESSAGE\n");
#endif
    //exit(1);
    //break;
  }

  return 0;
}

