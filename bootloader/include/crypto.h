
#ifndef DECRYPT_H
#define DECRYPT_H
#include <stdbool.h>


/* 
* Message format:
* 
* Components: SHA256 Hash | DSA Signed AES Key | RSA Encrypted AES Key | AES Encrypted Binary |
* Size      :    32B      |       320b         |        256B           |       (variable)     |
* 
*/

// return true if hash of data is correct
// changes buffer start to be one index past hash location at return
bool verify_hash(char* buffer, int* buffer_start);

// places decrypted message in dec_msg
// returns size of encrypted message, -1 if DSA signature fails
int decrypt(char* buffer, int buffer_start, char* dec_msg);

//returns size of encrypted message, places message in enc_msg
int encrypt(char* buffer, int buffer_start, char* enc_msg);

#endif
