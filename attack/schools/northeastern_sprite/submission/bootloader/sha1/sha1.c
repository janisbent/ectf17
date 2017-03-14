/* sha1.c */
/*
    This file is part of the AVR-Crypto-Lib.
    Copyright (C) 2008, 2009  Daniel Otte (daniel.otte@rub.de)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * \file	sha1.c
 * \author	Daniel Otte
 * \date	2006-10-08
 * \license GPLv3 or later
 * \brief SHA-1 implementation.
 *
 */

#include <stdint.h>
#include "sha1.h"
#include "crypto.h"
#include "config.h"

#if defined _AVR_
#include <avr/wdt.h>
#endif

/********************************************************************************************************/
/* AVR specific functions */

// Resets the watchdog timer by calling the builtin wdt_reset()
void sha1_watchdog_reset(void);

void sha1_watchdog_reset() {
	#if defined _AVR_
		wdt_reset();
	#endif
}

/********************************************************************************************************/
/* some helping functions */

// Bitshifts to rotate n left by bits bits
uint32_t rotl32(uint32_t n, uint8_t bits){
	return ((n<<bits) | (n>>(32-bits)));
}


// Changes the endian of the given uint32 via bitshifting
uint32_t change_endian32(uint32_t x){
	return (((x)<<24) | ((x)>>24) | (((x)& 0x0000ff00)<<8) | (((x)& 0x00ff0000)>>8));
}

/* three SHA-1 inner functions: Part of the definition of sha1*/
uint32_t ch(uint32_t x, uint32_t y, uint32_t z){
	return ((x&y)^((~x)&z));
}

uint32_t maj(uint32_t x, uint32_t y, uint32_t z){
	return ((x&y)^(x&z)^(y&z));
}

uint32_t parity(uint32_t x, uint32_t y, uint32_t z){
	return ((x^y)^z);
}

/********************************************************************************************************/
/**
 * \brief initialises given SHA-1 context. Initializes h inside the state struct to the initial internal states for sha-1. 
 *
 */
void sha1_init(sha1_ctx_t *state){
	state->h[0] = 0x67452301;
	state->h[1] = 0xefcdab89;
	state->h[2] = 0x98badcfe;
	state->h[3] = 0x10325476;
	state->h[4] = 0xc3d2e1f0;
	state->length = 0;
	sha1_watchdog_reset();
}

/********************************************************************************************************/
/**
 * \brief "add" a block to the hash
 * This is the core function of the hash algorithm. To understand how it's working
 * and what thoese variables do, take a look at FIPS-182. This is an "alternativ" implementation
 */
#define MASK 0x0000000f

typedef uint32_t (*pf_t)(uint32_t x, uint32_t y, uint32_t z);

void sha1_nextBlock(sha1_ctx_t *state, const uint8_t *block){
	uint32_t a[5];
	uint32_t w[16];
	uint32_t temp;
	uint8_t t, s;

	uint32_t k[4];
	k[0] = 0x5a827999;
	k[1] = 0x6ed9eba1;
	k[2] = 0x8f1bbcdc;
	k[3] = 0xca62c1d6;
	sha1_watchdog_reset();

	/* load the w array (changing the endian and so) */
	for(t=0; t<16; t++){
		w[t] = change_endian32(((uint32_t*)block)[t]);
		sha1_watchdog_reset();
	}

	/* load the state */
	a[0] = state->h[0];
	a[1] = state->h[1];
	a[2] = state->h[2];
	a[3] = state->h[3];
	a[4] = state->h[4];
	sha1_watchdog_reset();

	/* the fun stuff */
	for(t=0; t<=79; t++){
		s = t & MASK;
		if(t>=16){
			w[s] = rotl32( w[(s+13)&MASK] ^ w[(s+8)&MASK] ^ w[(s+ 2)&MASK] ^ w[s] ,1);
			sha1_watchdog_reset();
		}

		uint32_t dtemp;
		if (t >= 0 && t < 20) {
			dtemp = ch(a[1], a[2], a[3]);
		} else if (t >= 40 && t < 60) {
			dtemp = maj(a[1], a[2], a[3]);
		} else {
			dtemp = parity(a[1], a[2], a[3]);
		}
		sha1_watchdog_reset();

		temp = rotl32(a[0],5) + dtemp + a[4] + k[(int) (t/20)] + w[s];
		a[4] = a[3];
		a[3] = a[2];
		a[2] = a[1];
		a[1] = a[0];
		a[0] = temp;
		a[2] = rotl32(a[2],30); // we might also do rotr32(c,2)
		sha1_watchdog_reset();
	}

	/* update the state */
	for(t=0; t<5; ++t){
		state->h[t] += a[t];
		sha1_watchdog_reset();
	}
	state->length += 512;
}

/********************************************************************************************************/
void sha1_lastBlock(sha1_ctx_t *state, const uint8_t *block, uint16_t length){
	uint8_t lb[SHA1_BLOCK_BYTES] = {[0 ... SHA1_BLOCK_BYTES-1] = 0}; /* local block */

	while(length>=SHA1_BLOCK_BITS){
		sha1_nextBlock(state, block);
		length -= SHA1_BLOCK_BITS;
		block = (uint8_t*)block + SHA1_BLOCK_BYTES;
	}

	state->length += length;
	for (uint8_t i = 0; i < (length+7)>>3; i++) {
		lb[i] = block[i];
		sha1_watchdog_reset();
	}
	/* set the final one bit */
	lb[length>>3] |= 0x80>>(length & 0x07);

	if (length>512-64-1){ // not enouth space for 64bit length value
		sha1_nextBlock(state, lb);
		state->length -= 512;

		for (uint8_t i = 0; i < SHA1_BLOCK_BYTES; i++) {
			lb[i] = 0;
			sha1_watchdog_reset();
		}
	}

	/* store the 64bit length value */
	for (uint8_t i = 0; i < 8; i++){
		lb[56+i] = ((uint8_t*) &(state->length))[7-i];
		sha1_watchdog_reset();
	}

	sha1_nextBlock(state, lb);
}

/********************************************************************************************************/
void sha1_ctx2hash(uint8_t *dest, sha1_ctx_t *state) {
	for(uint8_t i = 0; i < 5; i++){
		((uint32_t*)dest)[i] = change_endian32(state->h[i]);
		sha1_watchdog_reset();
	}
}

/********************************************************************************************************/
void sha1(uint8_t *dest, const uint8_t *msg, uint32_t length){
	sha1_ctx_t s;
	sha1_init(&s);
	while(length & (~0x0001ff)){ /* length>=512 */
		sha1_nextBlock(&s, msg);
		msg = msg + SHA1_BLOCK_BITS/8; /* increment pointer to next block */
		length -= SHA1_BLOCK_BITS;
	}
	sha1_lastBlock(&s, msg, length);
	sha1_ctx2hash(dest, &s);
}


