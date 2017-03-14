#ifndef UTIL_H
#define UTIL_H

#include <avr/boot.h>

#define OK    ((uint8_t)0x00)
#define ERROR ((uint8_t)0x01)

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) < (b)) ? (b) : (a))

#define STR2INT(s) ((uint32_t) (s)[0] << 24 | \
                    (uint32_t) (s)[1] << 16 | \
                    (uint32_t) (s)[2] <<  8 | \
                    (uint32_t) (s)[3])

void BOOTLOADER_SECTION program_flash(uint32_t page_address, uint8_t *data);

#endif
