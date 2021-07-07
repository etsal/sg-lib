#include "ipc_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define HI_BYTE(x) ((x & 0xff00) >> 8)
#define LO_BYTE(x) (x & 0xff) 

sg_frame_ctx_t *frame_ctx;

static size_t needed_frames(size_t len) {
  size_t count = 0;
  size_t sofar = len - SG_INIT_PAYLOAD_SZ;
  ++count;
  while (sofar > 0) {
    sofar -= SG_CONT_PAYLOAD_SZ;
    ++count;
  }
  return count;
}

void print_sg_frame(sg_frame_t *frame) {
  // edivider();
  printf("cid \t%d\n", frame->cid);
  printf("type \t%x\n", frame->type);
  switch (frame->type) {
  case (INIT_FRAME):
    printf("cmd \t%x\n", frame->init.cmd);
    printf("bc \t%d\n", (frame->init.bclo | 0x1100) | (frame->init.bchi << 8));
    // printf("data \t%s\n", hexstring(frame->init.data));
    break;
  case (CONT_FRAME):
    printf("seq \t%x\n", frame->cont.seq);
    // printf("data \t%s\n", hexstring(frame->cont.data));
    break;
  default:
    printf("unknown frame type\n");
  }
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

  ctx->sofar = 0;

  ctx->total_cont = 0;
  ctx->next_cont = 0;
}

int process_frame(sg_frame_t *frame) {
  int data_len, recv;
  switch (frame->type) {

  case INIT_FRAME:
    frame_ctx->cid = frame->cid;
    data_len = (frame->init.bclo | 0x1100) | (frame->init.bchi << 8);
    if (frame_ctx->data_size < data_len) {
      // Resize
      free(frame_ctx->data);
      frame_ctx->data = (uint8_t *)malloc(data_len + 1);
      frame_ctx->data_len = data_len + 1;
    }
    memset(frame_ctx->data, 0, frame_ctx->data_size);
    memcpy(frame_ctx->data, frame->init.data, SG_INIT_PAYLOAD_SZ);
    // Number of continuation frames
    frame_ctx->total_cont = needed_frames(data_len) - 1;
    frame_ctx->next_cont = 1;
    // Number of bytes of data we are expecting
    frame_ctx->data_len = data_len;
    // Number of bytes of data we have
    frame_ctx->sofar +=
        (data_len > SG_INIT_PAYLOAD_SZ ? SG_INIT_PAYLOAD_SZ : data_len);
    break;

  case CONT_FRAME:
    if (frame->cont.seq != frame_ctx->next_cont) {
      printf("%s : Error, expecting sequence number %d recieved %d\n",
             frame->cont.seq, frame_ctx->next_cont);
      return 1;
    }

    // Calculate how much data to read
    recv = frame_ctx->data_len - frame_ctx->sofar;
    recv = (recv > SG_CONT_PAYLOAD_SZ) ? SG_CONT_PAYLOAD_SZ : recv;
    memcpy(frame_ctx->data + frame_ctx->sofar, frame->cont.data, recv);
    break;

  default:
    printf("%s : Unknown frame\n");
    return 1;
  }
  return 0;
}

int prepare_frames(uint32_t cid, uint8_t cmd, uint8_t *data, size_t data_len,
                   sg_frame_t ***frames, size_t *num_frames) {
  int tmp, sofar, send;
  sg_frame_t *frame;

  assert(cmd == GET_SG || cmd == PUT_SG || cmd == EXISTS_SG);

  tmp = needed_frames(data_len);
  *frames = malloc(tmp * (sizeof(sg_frame_t*)));
  *num_frames = 0;

  // Prepare init frame
  frame = malloc(sizeof(sg_frame_t));
  frame->cid = cid;
  frame->type = INIT_FRAME;
  frame->init.bchi = HI_BYTE(data_len);
  frame->init.bclo = LO_BYTE(data_len);
  memcpy(frame->init.data, data, SG_INIT_PAYLOAD_SZ);
  *frames[*num_frames++] = frame; // Save frame to frames

  // Prepare continuation frame
  sofar = SG_INIT_PAYLOAD_SZ;

  while (sofar > 0) {
    frame = malloc(sizeof(sg_frame_t));
    frame->cid = cid;
    frame->type = CONT_FRAME;
    frame->cont.seq = *num_frames;
    send = (data_len - sofar) > SG_CONT_PAYLOAD_SZ ? SG_CONT_PAYLOAD_SZ
                                                   : (data_len - sofar);
    memcpy(frame->cont.data, data + sofar, send);
    sofar += send;
    *frames[*num_frames++] = frame; // Save frame to frames
  }
 
  assert(tmp == *num_frames);
  return 0;
}

