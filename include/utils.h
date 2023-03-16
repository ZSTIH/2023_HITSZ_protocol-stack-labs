#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <time.h>

uint16_t checksum16(uint16_t *data, size_t len);

#define constswap16(x) ((((x)&0xFF) << 8) | (((x) >> 8) & 0xFF)) //为16位数据交换大小端
//为16位数据交换大小端
static inline uint16_t swap16(uint16_t x) {
    return ((x & 0xFF) << 8) | ((x >> 8) & 0xFF);
}
//为32位数据交换大小端
static inline uint32_t swap32(uint32_t x) {
    return
        (((x >> 0) & 0xFF) << 24) |
        (((x >> 8) & 0xFF) << 16) |
        (((x >> 16) & 0xFF) << 8) |
        (((x >> 24) & 0xFF) << 0);
}

static inline uint32_t min32(uint32_t a, uint32_t b) {
    return a < b ? a : b;
}

char *iptos(uint8_t *ip);
char *mactos(uint8_t *mac);
char *timetos(time_t timestamp);
uint8_t ip_prefix_match(uint8_t *ipa, uint8_t *ipb);



#endif
