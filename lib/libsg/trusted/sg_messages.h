#ifndef __SG_MESSAGES_H__
#define __SG_MESSAGES_H__

#include <stdint.h>

#include "ra_tls.h"

typedef enum { HEARTBEAT, INCOMING, MESSAGE } SG_HEADER_TYPE;

struct message_header {
  uint32_t type;         // Heartbeat or message
  uint32_t incoming_len; // If type=message this is populated with the size of
                         // the incoming message
  //uint8_t *data;
  // TODO: Heartbeat data
};


int prepare_and_send_updates(ratls_ctx_t *ctx, uint8_t *data, size_t data_len);
int process_message(ratls_ctx_t *ctx);


#endif
