
#ifndef DECRYPT_H
#define DECRYPT_H

#include <stdbool.h>

/*
 * Takes a 512B frame in i_data, decrypts and verifies authenticity, and 
 * adds the decrypted data to the buffer starting at buffer[buffer_start].
 *
 * Returns the size of the data added to buffer or -1 on failed verification.
 */
int decrypt_frame(unsigned char *frame, unsigned char *buffer, 
                  unsigned int buffer_start);

/*
 * Decrypts a 265B page in place
 */
void decrypt_page(unsigned char *data);


#endif
