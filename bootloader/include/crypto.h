
#ifndef DECRYPT_H
#define DECRYPT_H

#include <stdint.h>
#include <stdbool.h>

void decrypt_header(void *datap);

void decrypt_body(uint16_t body);

bool valid_nonce(uint16_t nonce);

#endif
