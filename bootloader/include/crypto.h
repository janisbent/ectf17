
#ifndef DECRYPT_H
#define DECRYPT_H

#include <stdint.h>
#include <stdbool.h>

void decrypt(unsigned char *data, uint16_t size);

bool valid_nonce(uint32_t nonce);

#endif
