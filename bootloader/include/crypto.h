
#ifndef DECRYPT_H
#define DECRYPT_H

#include <stdint.h>

/*
 * Decrypts a 512B frame encrypted with RSA into 
 * an 8B nonce and a 256B page
 */
void decrypt_rsa(unsigned char *data);

/*
 * Decrypts a 265B page encrypted with AES
 */
void decrypt_aes(unsigned char *data);

#endif
