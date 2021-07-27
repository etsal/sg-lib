#ifndef __BASE_64_H__
#define __BASE_64_H__

unsigned char *base64_encode(
    const unsigned char *src, size_t len, size_t *out_len);

void base64_encode_wbuf(
    const unsigned char *src, size_t len, unsigned char *out, size_t *out_len);

unsigned char *base64_decode(
    const unsigned char *src, size_t len, size_t *out_len);

void base64_decode_wbuf(
    const unsigned char *src, size_t len, unsigned char *out, size_t *out_len);

#endif
