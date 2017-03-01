#ifndef DECRYPT_H
#define DECRYPT_H

/* Assumes the buffer length is 16 bytes */ 
void decrypt(uint8_t *enc_data, uint8_t* dec_data);

/* Assumes the buffer's length is 16 bytes */
void encrypt(uint8_t *dec_data, uint8_t* enc_data);

#endif
