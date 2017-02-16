#include "crypto.h"

char priv_key[] EEMEM = PRIVATE_KEY;

char publ_key[] EEMEM = PUBLIC_KEY;

int decrypt_frame(unsigned char *frame, unsigned char *buffer, 
                  unsigned int buffer_start){
	return 1;
}

void encrypt_frame(unsigned char *frame, unsigned char *buffer,
                   unsigned int size) {
	return;
}
