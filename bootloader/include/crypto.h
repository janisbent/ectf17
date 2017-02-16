
#ifndef DECRYPT_H
#define DECRYPT_H

#include <stdbool.h>
#include <avr/pgmspace.h>
#include <avr/boot.h>
#include <avr/interrupt.h>
#include <avr/wdt.h>

/*
 * Takes a 1024B frame in i_data, decrypts and verifies authenticity, and 
 * adds the decrypted data to the buffer starting at buffer[buffer_start]
 *
 * Returns the size of the data added to buffer or -1 on failed verification
 */
int decrypt_frame(unsigned char *frame, unsigned char *buffer, 
                  unsigned int buffer_start);

/*
 * Accepts data of size bytes in buffer (must be under 470B) and places
 * encrypted 512B frame into frame
 */
void encrypt_frame(unsigned char *frame, unsigned char *buffer,
                   unsigned int size);



#endif
