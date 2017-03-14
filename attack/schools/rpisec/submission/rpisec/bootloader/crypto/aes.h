#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

#define AES_BLOCK_SIZE 16

void AES128_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);
void AES128_CBC_decrypt_buffer(uint8_t* data, uint32_t length, const uint8_t* key, const uint8_t* iv);

#endif //_AES_H_
