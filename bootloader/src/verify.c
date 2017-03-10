#include "dsa_verify.h"
#include "verify.h"

#define SHA_LEN 256

//returns 0 on sucess and 1 on fail
int dsa_verify(uint8_t* message, uint8_t* R, uint8_t* S){
   return dsa_verify_blob(message, SHA_LEN, DSA_KEY, R, S);
}

bool verify_hash(uint8_t* buffer, int buffer_start){
   uint8_t hash[SHA256_HASH_BYTES];
   uint8_t data[SHA_LEN];
   uint8_t orig_hash[SHA256_HASH_BYTES];
   int sum = 0;   

   memcpy_P(data, buffer+SHA256_HASH_BYTES, SHA_LEN);
   memcpy_P(orig_hash, buffer, SHA256_HASH_BYTES);
   sha256((sha256_hash_t*)hash, data, SHA_LEN * 8);
   
   for(int i = 0; i < SHA_LEN; i++){
         sum = sum + ((hash + i) ^ (orig_hash + i));
   }

   return !sum;
}
