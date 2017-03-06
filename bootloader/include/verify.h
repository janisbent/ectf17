#ifndef VERIFY_H
#define VERIFY_H

int dsa_verify(uint8_t* message, uint8_t* R, uint8_t* S);
bool verify_hash(uint8_t* buffer, int buffer_start);

#endif
