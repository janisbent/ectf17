/*
 * AES configuration headers.
 */


#ifndef AES_H_
#define AES_H_

#include <stdint.h>

void AES128_ECB_encrypt(const uint8_t* input, const uint8_t * key, uint8_t * output);

void AES128_ECB_decrypt(const uint8_t* input, const uint8_t * key, uint8_t * output);

#endif /* AES_H_ */
