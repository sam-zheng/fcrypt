#ifndef CRC_H_
#define CRC_H_

#include <stddef.h>
#include <stdint.h>

#define POLY 0xEDB88320 /* 0x04C11DB7 bits reversed */

uint32_t calc_file_crc(char *file);
uint32_t calc_crc(char *data, size_t size);
uint32_t calc(void* ctx, size_t (*_next)(void* ctx, char *, size_t));

void *ctx_init();
void sum(void *ctx, char *b, size_t n);
uint32_t done(void *ctx);

#endif /* CRC_H_ */
