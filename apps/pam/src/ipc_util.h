#ifndef __IPC_UTIL_H__
#define __IPC_UTIL_H__

#include <stdint.h>
#include <stddef.h>

#define SG_FRAME_SZ 128
#define SG_INIT_PAYLOAD_SZ (SG_FRAME_SZ - 8)
#define SG_CONT_PAYLOAD_SZ (SG_FRAME_SZ - 6)

typedef enum { GET_SG, PUT_SG, EXISTS_SG, DEFAULT_SG } sg_cmd_t;
typedef enum { INIT_FRAME, CONT_FRAME } sg_type_t;

typedef struct sg_frame {
  uint32_t cid; // Channel identifier
  uint8_t type; // Msg type
  union {
    struct {
      uint8_t cmd;                 // Command
      uint8_t bchi;                // Byte count low
      uint8_t bclo;                // Byte count high
      uint8_t data[SG_FRAME_SZ - 8]; // Data payload
    } init;
    struct {
      uint8_t seq; // Sequence number
      uint8_t data[SG_FRAME_SZ - 6];
    } cont;
  };
} sg_frame_t;

typedef struct sg_frame_ctx {
  uint32_t cid;
  uint8_t *data;
  size_t data_size;
  size_t data_len;
  size_t sofar;
  int total_cont;
  int next_cont;

} sg_frame_ctx_t;

void print_sg_frame(sg_frame_t *frame);
void init_sg_frame_ctx(sg_frame_ctx_t *ctx);
int process_frame(sg_frame_t *frame);
int prepare_frames(uint32_t cid, uint8_t cmd, uint8_t *data, size_t data_len,
                   sg_frame_t ***frames, size_t *num_frames);


#endif
