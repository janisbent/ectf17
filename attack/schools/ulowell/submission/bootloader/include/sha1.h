/*
 * sha1  headers.
 */

#ifndef SHA1_H_
#define SHA1_H_

#include <stdint.h>

void sha1_init(uint32_t * h);

void pad_msg(unsigned char *inmsg, unsigned char *msg, int message_length, uint32_t l);

void sha1_loop(uint32_t *h, unsigned char *message);

void gen_digest(uint32_t * h, uint8_t *digest);

#endif /* SHA1_H_ */
