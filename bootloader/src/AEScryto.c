#include "crypto.h"
#include "aes/aes.h"

#include "bcal/bcal_aes128.h"
#include "bcal/bcal_aes192.h"
#include "bcal/bcal_aes256.h"
#include "bcal/bcal-cbc.h"
#include "bcal/bcal-cfb_byte.h"
#include "bcal/bcal-cfb_bit.h"
#include "bcal/bcal-ofb.h"
#include "bcal/bcal-ctr.h"
#include "bcal/bcal-cmac.h"
#include "bcal/bcal-eax.h"
// #include "cmacvs.h"
#include "bcal/bcal-performance.h"
#include "bcal/bcal-nessie.h"

//TODO remove these and read in from file
const uint8_t modes_key[]   EEMEM = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
		0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
	};
const uint8_t modes_iv[]    EEMEM = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

const uint8_t modes_plain[] PROGMEM = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		/* --- */
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
		0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		/* --- */
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		/* --- */
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
		0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };

const bcdesc_t aes128_desc;

int decrypt_frame(unsigned char *frame, unsigned char *buffer, 
                  unsigned int buffer_start) {

// TODO NEED TO CHECK LENGTH??
// if (data_len % 16 != 0) {
// 		return;
// 	}

	uint8_t key[16];
	uint8_t iv[16];
	uint8_t plain[64];

	bcal_cbc_ctx_t ctx;
	uint8_t r;

	memcpy_P(key,   modes_key,   16);
	memcpy_P(iv,    modes_iv,    16);
	memcpy_P(plain, modes_plain, 64);

	r = bcal_cbc_init(&aes128_desc, key, 128, &ctx);
	if(r)
		return 1;
	bcal_cbc_decMsg(iv, plain, 4, &ctx);
	buffer[buffer_start] = plain;
	bcal_cbc_free(&ctx);
	return 0//size of output always = input but i think 1 is fine

}

int encrypt_frame(unsigned char *frame, unsigned char *buffer,
                   unsigned int size) {
	uint8_t key[16];
	uint8_t iv[16];
	uint8_t plain[64];

	bcal_cbc_ctx_t ctx;
	uint8_t r;

	memcpy_P(key,   modes_key,   16);
	memcpy_P(iv,    modes_iv,    16);
	memcpy_P(plain, modes_plain, 64);

	r = bcal_cbc_init(&aes128_desc, key, 128, &ctx);
	
	//TODO assuming this is error check but need to confirm
	if(r)
		return 1;
	bcal_cbc_encMsg(iv, plain, 4, &ctx);
	buffer[buffer_start] = plain;
	bcal_cbc_free(&ctx);

    return 0;
}

// http://etutorials.org/Programming/secure+programming/Chapter+7.+Public+Key+Cryptography/7.13+Verifying+Signed+Data+Using+an+RSA+Public+Key/
// TODO:
//int verify(unsigned char *msg, unsigned int mlen, unsigned char *sig,
//                unsigned int siglen, RSA *r) {
// 	unsigned char hash[20];
// 	BN_CTX        *c;
// 	int           ret;

// 	if (!(c = BN_CTX_new())) {
// 		return 0;
// 	} 
// 	if (!SHA1(msg, mlen, hash) || !RSA_blinding_on(r, c)) {
// 		BN_CTX_free(c);
// 		return 0;
// 	}

// 	ret = RSA_verify(NID_sha1, hash, 20, sig, siglen, r);
// 	RSA_blinding_off(r);
// 	BN_CTX_free(c);
// 	return ret;
// }

