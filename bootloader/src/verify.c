#include <stdint.h>
#include <stdbool.h>
#include <avr/pgmspace.h>

#include "dsa_verify.h"
#include "sha1.h"
#include "uart.h"
#include "verify.h"
// #include "keys.h"

// The length of a sha1 hash is 160 bits, or 20 bytes

#define SHA_LEN_BYTES 20
#define FRAME_BYTES 16

/* TEMPORARY HARD-CODED DSA KEY TO SILENCE COMPILER WARNINGS
 * REMOVE AT A LATER DATE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! 
 */
const unsigned char *DSA_KEY = (unsigned char*) "1234567812345678";

//returns 0 on sucess and 1 on fail
int dsa_verify(uint8_t* message, uint8_t* R, uint8_t* S){
   return dsa_verify_blob(message, SHA_LEN_BYTES, DSA_KEY, R, S);
   // Never reached
   return -1;
}

bool verify_hash(uint8_t* buffer, int buffer_start) {
   // Declare and initialize the SHA1 context   
   SHA1Context *context = 0x0;
   SHA1Reset(context);

   uint8_t hash[SHA_LEN_BYTES];
   uint8_t precomp_hash[SHA_LEN_BYTES];
   uint8_t data[FRAME_BYTES];
   
   int sum = 0;   

   memcpy_P(precomp_hash, buffer, SHA_LEN_BYTES);
   memcpy_P(data, buffer + SHA_LEN_BYTES, FRAME_BYTES);

   SHA1Input(context, data, FRAME_BYTES);
   SHA1Result(context, hash);
   
   for (int i = 0; i < SHA_LEN_BYTES; i++) {
         sum = sum + ((*(hash + i)) ^ (*(precomp_hash + i)));
   }

   return !sum;
}
