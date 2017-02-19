
#ifndef DECRYPT_H
#define DECRYPT_H

#include <stdbool.h>
#include <stdio.h>
#include <avr/pgmspace.h>
#include <avr/boot.h>
#include <avr/interrupt.h>
#include <avr/wdt.h>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

/*
 * Takes a 512B frame in i_data, decrypts and verifies authenticity, and 
 * adds the decrypted data to the buffer starting at buffer[buffer_start]
 *
 * Returns the size of the data added to buffer or -1 on failed verification
 */
int decrypt_frame(unsigned char *frame, unsigned char *buffer, 
                  unsigned int buffer_start);

/*
 * Accepts data of size bytes in buffer (must be under 214B) and places
 * encrypted 256B frame into frame. Returns size of encrypted data.
 */
int encrypt_frame(unsigned char *frame, unsigned char *buffer,
                   unsigned int size);



#endif
