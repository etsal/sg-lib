#include "ipc_util.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HI_BYTE(x) ((x & 0xff00) >> 8)
#define LO_BYTE(x) (x & 0xff)

static char *_hex_buffer = NULL;
static size_t _hex_buffer_size = 0;
static const char _hextable[] = "0123456789abcdef";

static const char *hexstring(const void *vsrc, size_t len) {
  size_t i, bsz;
  const unsigned char *src = (const unsigned char *)vsrc;
  char *bp, *tmp;

  bsz = len * 2 + 1; /* Make room for NULL byte */
  if (bsz >= _hex_buffer_size) {
    /* Allocate in 1K increments. Make room for the NULL byte. */

    /*
            tmp = malloc(new_sz);
            memcpy(tmp, _hex_buffer, _hex_buffer_size);
            _hex_buffer_size= newsz;
            free(_hex_buffer);
           _hex_buffer= tmp;

      */
    size_t newsz = 1024 * (bsz / 1024) + ((bsz % 1024) ? 1024 : 0);
    _hex_buffer_size = newsz;
    _hex_buffer = (char *)realloc(_hex_buffer, newsz);
    if (_hex_buffer == NULL) {
      return "(out of memory)";
    }
  }
  unsigned int idx = 0;
  for (i = 0, bp = _hex_buffer; i < len; ++i) {
    idx = (src[i] >> 4) % strlen(_hextable);
    *bp = _hextable[idx];
    ++bp;
    *bp = _hextable[src[i] & 0xf];
    ++bp;
  }
  _hex_buffer[len * 2] = 0;

  return (const char *)_hex_buffer;
}

static size_t needed_frames(size_t len) {
  size_t count = 1;
  int sofar = len - SG_INIT_PAYLOAD_SZ;
  while (sofar > 0) {
    sofar -= SG_CONT_PAYLOAD_SZ;
    ++count;
  }
  return count;
}

void print_sg_frame(sg_frame_t *frame) {
  // edivider();
  char init[] = "INIT";
  char cont[] = "CONT";
  char buf[512];

  memset(buf, '-', sizeof(buf));
  snprintf(buf, sizeof(buf), "--- %s ",
           (frame->type == INIT_FRAME) ? init : cont);
  buf[strlen(buf)] = '-';
  buf[30] = '\0';

  printf("%s\n", buf);
  printf("cid \t%d\n", frame->cid);
  printf("type \t%x\n", frame->type);
  switch (frame->type) {
  case (INIT_FRAME):
    printf("bc \t%d\n", (frame->init.bclo) | (frame->init.bchi << 8));
    printf("data %s\n", hexstring(frame->init.data, SG_INIT_PAYLOAD_SZ));

    break;
  case (CONT_FRAME):
    printf("seq \t%x\n", frame->cont.seq);
    printf("data %s\n", hexstring(frame->cont.data, SG_CONT_PAYLOAD_SZ));
    break;
  default:
    printf("unknown frame type\n");
  }

  memset(buf, '-', sizeof(buf));
  buf[30] = '\0';

  printf("%s\n", buf);
  // edivider();
}

void init_sg_frame_ctx(sg_frame_ctx_t *ctx) {
  /*
    key_size = 128;
    key = malloc(key_size * sizeof(char));
    key_len = 0;

    value_size = 256;
    value = malloc(value_size * sizeof(uint8_t));
    value_len = 0;
    */
  ctx->cid = 0;

  ctx->data_size = 256;
  ctx->data = malloc(ctx->data_size * sizeof(uint8_t));
  ctx->data_len = 0;
  memset(ctx->data, 0, ctx->data_size);

  ctx->sofar = 0;

  ctx->total_cont = 0;
  ctx->recv_cont = 0;
}

void clear_sg_frame_ctx(sg_frame_ctx_t *ctx) {
  ctx->cid = 0;

  // ctx->data_size = 256;
  memset(ctx->data, 0, ctx->data_size);
  ctx->data_len = 0;

  ctx->sofar = 0;

  ctx->total_cont = 0;
  ctx->recv_cont = 0;
}

void free_sg_frame_ctx(sg_frame_ctx_t *ctx) { free(ctx->data); }

/* Returns 0 if we are waiting for more data, 1 if we have all frames, -1 on
 * error
 */
int process_frame(sg_frame_t *frame, sg_frame_ctx_t *frame_ctx) {
  int data_len, recv;
  switch (frame->type) {

  case INIT_FRAME:
    frame_ctx->cid = frame->cid;
    data_len = (frame->init.bclo) | (frame->init.bchi << 8);
    if (frame_ctx->data_size < data_len) {
      // Resize
      free(frame_ctx->data);
      frame_ctx->data = (uint8_t *)malloc(data_len + 1);
      frame_ctx->data_size = data_len + 1;
    }
    memset(frame_ctx->data, 0, frame_ctx->data_size);
    memcpy(frame_ctx->data, frame->init.data, SG_INIT_PAYLOAD_SZ);
    // Number of continuation frames
    frame_ctx->total_cont = needed_frames(data_len) - 1;
    frame_ctx->recv_cont = 0; //(frame_ctx->total_cont == 0) ? 0 : 1;
    // Number of bytes of data we are expecting
    frame_ctx->data_len = data_len;
    // Number of bytes of data we have
    frame_ctx->sofar +=
        (data_len > SG_INIT_PAYLOAD_SZ ? SG_INIT_PAYLOAD_SZ : data_len);

    break;

  case CONT_FRAME:
    // Sequence number should be +1 of the cont frames recieved
    if (frame->cont.seq != (frame_ctx->recv_cont + 1)) {
      printf("%s : Error, expecting sequence number %d recieved %d\n",
             __FUNCTION__, frame->cont.seq, frame_ctx->recv_cont);
      return -1;
    }

    // Calculate how much data to read
    recv = frame_ctx->data_len - frame_ctx->sofar;
    if (recv > SG_CONT_PAYLOAD_SZ) {
      recv = SG_CONT_PAYLOAD_SZ;
      //++frame_ctx->recv_cont;
    }

    memcpy(frame_ctx->data + frame_ctx->sofar, frame->cont.data, recv);
    frame_ctx->sofar += recv;
    frame_ctx->recv_cont += 1;
    break;

  default:
    printf("%s : Unknown frame\n");
    return -1;
  }

  /* DEBUG
  if (frame_ctx->total_cont == frame_ctx->recv_cont)
    printf("%s : frame_ctx.data (len %d) : %s\n", __FUNCTION__,
           frame_ctx->data_len,
           hexstring(frame_ctx->data, frame_ctx->data_len));
  */

  return (frame_ctx->total_cont == frame_ctx->recv_cont);
}

void free_frames(sg_frame_t **frames[], size_t num_frames) {
  for (int i = 0; i < num_frames; ++i) {
    free((*frames)[i]);
  }
  free(*frames);
  *frames = NULL;
}

int prepare_frames(uint32_t cid, uint8_t *data, size_t data_len,
                   sg_frame_t **frames[], size_t *num_frames) {
  int tmp, sofar, send;
  sg_frame_t *frame;

  // assert(cmd == GET_SG || cmd == PUT_SG || cmd == EXISTS_SG);

  tmp = needed_frames(data_len);
  *frames = malloc(tmp * (sizeof(sg_frame_t *)));
  *num_frames = 0;

  // Prepare init frame
  frame = malloc(sizeof(sg_frame_t));
  frame->cid = cid;
  frame->type = INIT_FRAME;
  frame->init.bchi = HI_BYTE(data_len);
  frame->init.bclo = LO_BYTE(data_len);
  memcpy(frame->init.data, data, SG_INIT_PAYLOAD_SZ);
  *frames[*num_frames] = frame; // Save frame to frames
  *num_frames += 1;

  // Prepare continuation frame
  sofar = SG_INIT_PAYLOAD_SZ;

  while (sofar < data_len) {
    // printf("%s : data_len %d, sofar %d\n", __FUNCTION__, data_len, sofar);
    frame = (sg_frame_t *)malloc(sizeof(sg_frame_t));
    memset(frame, 0, sizeof(sg_frame_t));

    frame->cid = cid;
    frame->type = CONT_FRAME;
    frame->cont.seq = *num_frames;
    send = (data_len - sofar) > SG_CONT_PAYLOAD_SZ ? SG_CONT_PAYLOAD_SZ
                                                   : (data_len - sofar);
    memcpy(frame->cont.data, data + sofar, send);
    sofar += send;
    (*frames)[(*num_frames)] = frame; // Save frame
    *num_frames += 1;
  }

  // printf("%s : data_len %d, sofar %d\n", __FUNCTION__, data_len, sofar);
  // printf("%s : tmp %d num_frames %d\n", __FUNCTION__, tmp, *num_frames);

  assert(tmp == *num_frames);

  return 0;
}

