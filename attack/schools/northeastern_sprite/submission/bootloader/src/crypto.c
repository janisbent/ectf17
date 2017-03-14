/*
 * keys.c
 */

#include <stdint.h>
#include <string.h>
#include "sha1.h"
#include "crypto.h"
#include "message.h"
#include "config.h"

#if defined _AVR_
#include <avr/pgmspace.h>
#include <avr/wdt.h>
#endif

/* Public constants and retrieval methods */
#if defined _AVR_
	const uint8_t public_a[16] PROGMEM = 	{126, 240, 89, 224, 211, 132, 229, 36, 228, 158, 151, 95, 157, 190, 62, 138};
	const uint8_t public_b[16] PROGMEM = 	{35, 18, 187, 47, 160, 40, 169, 208, 91, 53, 137, 125, 251, 230, 94, 247};
    // Polynomial constants needed for crypto
	const uint8_t sub_polynomials[15][16] PROGMEM = {
											{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20},
											{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0},
											{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0},
											{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0},
											{0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0},
											{0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0},
											{0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0},
											{0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0},
											{0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0},
											{0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0},
											{0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
											{0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
											{1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
											{0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20},
											{1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0}};

	/* Loaders for these constants (from progmem) 
	   We load these from progmem because there is not enough ram to constantly store these */
	// Load a
	void load_public_a(uint8_t *destination) {
		for (uint8_t i = 0; i < 16; i++) {
			destination[i] = (uint8_t) pgm_read_byte_far(&(public_a[i]));
		}
	}

    // Load b
	void load_public_b(uint8_t *destination) {
		for (uint8_t i = 0; i < 16; i++) {
			destination[i] = (uint8_t) pgm_read_byte_far(&(public_b[i]));
		}
	}

    // load the polynomial constants
	uint8_t load_sub_polynomial(uint8_t i, uint8_t j) {
		return (uint8_t) pgm_read_byte_far(&(sub_polynomials[i][j]));
	}
#else

	static const uint8_t public_a[16] = 	{126, 240, 89, 224, 211, 132, 229, 36, 228, 158, 151, 95, 157, 190, 62, 138};
	static const uint8_t public_b[16] = 	{35, 18, 187, 47, 160, 40, 169, 208, 91, 53, 137, 125, 251, 230, 94, 247};

	static const uint8_t sub_polynomials[15][16] = {
											{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20},
											{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0},
											{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0},
											{0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0},
											{0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0},
											{0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0},
											{0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0},
											{0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0},
											{0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0},
											{0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0},
											{0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
											{0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
											{1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
											{0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20},
											{1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0}};

	/* Loaders for these constants */
	void load_public_a(uint8_t *destination) {
		for (uint8_t i = 0; i < 16; i++) {
			destination[i] = public_a[i];
		}
	}

	void load_public_b(uint8_t *destination) {
		for (uint8_t i = 0; i < 16; i++) {
			destination[i] = public_b[i];
		}
	}

	uint8_t load_sub_polynomial(uint8_t i, uint8_t j) {
		return sub_polynomials[i][j];
	}
#endif

/********************************************************************************************************/
/* Function prototypes */
void crypt_watchdog_reset(void);

uint8_t add_coefficients(const uint8_t, const uint8_t);
uint8_t multiply_coefficients(uint8_t, uint8_t);
void reduce_polynomial(const uint8_t*, uint8_t*);
void multiply_polynomials(const uint8_t*, const uint8_t*, uint8_t*);

/********************************************************************************************************/
/* AVR specific functions */
void crypt_watchdog_reset() {
	#if defined _AVR_
		wdt_reset();
	#endif
}

/********************************************************************************************************/
/* Initialize the array with all 0s */
void init_block(uint8_t *block, const uint8_t num_bytes) {
	for (uint8_t i = 0; i < num_bytes; i++) {
		block[i] = 0;
		crypt_watchdog_reset();
	}
}

/* Copy contents of source to destination given ranges of source and destination 
   This is a general utility function used throughout this codebase when copying blocks of data */
void copy_block(const uint8_t *source, uint8_t *destination, const uint8_t source_start, const uint8_t destination_start, const uint8_t num_bytes) {
	for (uint8_t i = 0; i < num_bytes; i++) {
		destination[i + destination_start] = source[i + source_start];
		crypt_watchdog_reset();
	}
}

/* Xor 2 arrays of uint8s*/
void xor_blocks(const uint8_t *block1, const uint8_t *block2, uint8_t *result, const uint8_t num_bytes) {
	for (uint8_t i = 0; i < num_bytes; i++) {
		result[i] = block1[i] ^ block2[i];
		crypt_watchdog_reset();
	}
}

/********************************************************************************************************/
// Holds arithmetic operations in GF(8). See http://homepages.math.uic.edu/~leon/mcs425-s08/handouts/field.pdf for a brief introduction

/* Add two binary polynomials in GF(8). In GF(8), this is defined as xoring them. */
uint8_t add_coefficients(const uint8_t x, const uint8_t y) {
	return x ^ y;
}

/* Multiply two binary polynomials in GF(8). See the above link for an explanation of what GF(8) is and how it works*/
uint8_t multiply_coefficients(uint8_t x, uint8_t y) {
	uint8_t p = 0;

	while (y) {
		if (y & 1)
			p ^= x;
		if (x & 0x80)
			x = (x << 1) ^ 0x11b;
		else
			x <<= 1;
		y >>= 1;
	}

	return p;
}

/* Reduce polynomial using the irreducible polynomial matrix */
void reduce_polynomial(const uint8_t *poly, uint8_t *result) {
	uint8_t tmp_result[POLY_DEG];
	init_block(tmp_result, POLY_DEG);

	// Go through x16 to x30 and replace them
	for (uint8_t i = 0; i < 15; i++) {
		uint8_t sub_polynomial[POLY_DEG];
		init_block(sub_polynomial, POLY_DEG);

		// Get the coeff for xi, 15< i <31
		uint8_t sub_coefficient = poly[i];

		if (sub_coefficient != 0) {
			for (uint8_t j = 0; j < POLY_DEG; j++) {
				// 14-j because x30 is at the subpoly[14] but is the mult_poly[0]
				sub_polynomial[j] = multiply_coefficients(load_sub_polynomial(14-i, j), sub_coefficient);
				crypt_watchdog_reset();
			}

			// Add up all the subpolies and store in result
			for (uint8_t k = 0; k < POLY_DEG; k++) {
				tmp_result[k] = add_coefficients(tmp_result[k], sub_polynomial[k]);
				crypt_watchdog_reset();
			}
		}
	}

	init_block(result, POLY_DEG);
	for (uint8_t j = 0; j < POLY_DEG; j++) {
		// j+15, since mult_poly is of degree 31
		result[j] = add_coefficients(tmp_result[j], poly[j+15]);
		crypt_watchdog_reset();
	}
}

/* Multiply two polynomials */
void multiply_polynomials(const uint8_t *poly1, const uint8_t *poly2, uint8_t *result) {
	init_block(result, MULT_DEG);

	for (uint8_t i = 0; i < POLY_DEG; i++) {
		for (uint8_t j = 0; j < POLY_DEG; j++) {
			// For each mononomial, multiply them using coeff_mult (* in GF(8)) and
			// add them using coeff_add (+ in GF(8))
			result[i+j] = add_coefficients(result[i+j], multiply_coefficients(poly1[i], poly2[j]));
			crypt_watchdog_reset();
		}
	}
}

/********************************************************************************************************/
/* Generate temp keys using initial seed and the pre-shared master key */
void generate_random_keys(crypt_keys_t *keys) {
	uint8_t tmp_hash[SHA1_HASH_BYTES];
	uint8_t tmp_xor[KEY_SIZE];
	init_block(tmp_xor, KEY_SIZE);

	// For n-1 keys, generate the key using the previous seed and sha1 hashes
	for (uint8_t i = 0; i < TEMP_KEYS-1; i++) {
		// The key is the first 16 bytes of hash of seed
		sha1(tmp_hash, keys->rand, SHA1_HASH_BYTES * 8);
		copy_block(tmp_hash, keys->tmp_key[i], 0, 0, KEY_SIZE);

		// The new seed is the first 16 bytes of hash of seed[j]+1
		for (uint8_t j = 0; j < SHA1_HASH_BYTES; j++)
			keys->rand[j]++;
		sha1(tmp_hash, keys->rand, SHA1_HASH_BYTES * 8);
		copy_block(tmp_hash, keys->rand, 0, 0, SHA1_HASH_BYTES);

		// Xor this key with the temp buffer
		xor_blocks(tmp_xor, keys->tmp_key[i], tmp_xor, KEY_SIZE);
	}

	// Update the new seed in the EEPROM
	config_update_seed(keys);

	// The last key is obtained by XORing k[] and secret
	xor_blocks(tmp_xor, keys->key, keys->tmp_key[TEMP_KEYS-1], KEY_SIZE);
}

/* Generate a secret key (k0) from the temp keys and the f* function */
void generate_encryption_key(const uint8_t *hash, crypt_keys_t *keys) {
	uint8_t tmp_mult[MULT_DEG];
	uint8_t tmp_red[POLY_DEG];
	uint8_t tmp_xor[KEY_SIZE];
	init_block(tmp_xor, KEY_SIZE);

	// For each key, calculate the f* with hash. Xor with the prev value
	for (uint8_t i = 0; i < TEMP_KEYS; i++) {
		multiply_polynomials(hash, keys->tmp_key[i], tmp_mult);
		reduce_polynomial(tmp_mult, tmp_red);
		xor_blocks(tmp_xor, tmp_red, tmp_xor, KEY_SIZE);
	}

	// Copy the final xor output to form our k0
	copy_block(tmp_xor, keys->key0, 0, 0, KEY_SIZE);
}

/********************************************************************************************************/
/* Initialize the struct that will be used for storing the keys */
void crypt_init(const uint8_t *hash, crypt_keys_t *keys) {
	// Initialize all the keys
	for (uint8_t i = 0; i < TEMP_KEYS; i++) {
		init_block(keys->tmp_key[i], KEY_SIZE);
		crypt_watchdog_reset();
	}

	// Generate temp random keys
	generate_random_keys(keys);
	// Generate k0 from the temp keys
	generate_encryption_key(hash, keys);
}

/* Encrypt the plaintext to the ciphertext one block at a time */
void crypt_encrypt(const uint8_t* plain_text, uint8_t *cipher_text, crypt_keys_t *keys, const uint8_t len) {
	uint8_t tmp_hash[SHA1_HASH_BYTES];
	uint8_t tmp_plain[BLOCK_SIZE];
	uint8_t tmp_cipher[BLOCK_SIZE];
	uint8_t tmp_text[KEY_SIZE + BLOCK_SIZE];

	// Load public constants a and b (from progmem for avr)
	uint8_t tmp_pub_a[16];
	load_public_a(tmp_pub_a);
	uint8_t tmp_pub_b[16];
	load_public_b(tmp_pub_b);

	// Iterate through each block of data and perform encryption
	init_block(cipher_text, len);
	for (uint8_t i = 0; i < len; i = i + BLOCK_SIZE) {
		// Hash the key k0 and public constant b together
		copy_block(keys->key0, tmp_text, 0, 0, KEY_SIZE);
		copy_block(tmp_pub_b, tmp_text, 0, KEY_SIZE, BLOCK_SIZE);
		sha1(tmp_hash, tmp_text, (KEY_SIZE + BLOCK_SIZE) * 8);

		// Xor 16 bytes of hash and plaintext to obtain the ciphertext
		copy_block(plain_text, tmp_plain, i, 0, BLOCK_SIZE);
		xor_blocks(tmp_hash, tmp_plain, tmp_cipher, BLOCK_SIZE);
		copy_block(tmp_cipher, cipher_text, 0, i, BLOCK_SIZE);

		// Hash the key k0 and public constant a to generate new k0
		copy_block(tmp_pub_a, tmp_text, 0, KEY_SIZE, BLOCK_SIZE);
		sha1(tmp_hash, tmp_text, (KEY_SIZE + BLOCK_SIZE) * 8);
		copy_block(tmp_hash, keys->key0, 0, 0, KEY_SIZE);
	}
}

/* Decrpyt the ciphertext to the plaintext one block at a time */
void crypt_decrypt(const uint8_t* cipher_text, uint8_t *decrypted_text, crypt_keys_t *keys, const uint8_t len) {
	uint8_t tmp_hash[SHA1_HASH_BYTES];
	uint8_t tmp_cipher[BLOCK_SIZE];
	uint8_t tmp_decrypt[BLOCK_SIZE];
	uint8_t tmp_text[KEY_SIZE + BLOCK_SIZE];

	// Load public constants a and b (from progmem for avr)
	uint8_t tmp_pub_a[16];
	load_public_a(tmp_pub_a);
	uint8_t tmp_pub_b[16];
	load_public_b(tmp_pub_b);

	// Iterate through each block of data and perform decryption
	init_block(decrypted_text, len);
	for (uint8_t i = 0; i < len; i = i + BLOCK_SIZE) {
		// Hash the key k0 and public constant b together
		copy_block(keys->key0, tmp_text, 0, 0, KEY_SIZE);
		copy_block(tmp_pub_b, tmp_text, 0, KEY_SIZE, BLOCK_SIZE);
		sha1(tmp_hash, tmp_text, (KEY_SIZE + BLOCK_SIZE) * 8);

		// Xor 16 bytes of hash and plaintext to obtain the ciphertext
		copy_block(cipher_text, tmp_cipher, i, 0, BLOCK_SIZE);
		xor_blocks(tmp_hash, tmp_cipher, tmp_decrypt, BLOCK_SIZE);
		copy_block(tmp_decrypt, decrypted_text, 0, i, BLOCK_SIZE);

		// Hash the key k0 and public constant a to generate new k0
		copy_block(tmp_pub_a, tmp_text, 0, KEY_SIZE, BLOCK_SIZE);
		sha1(tmp_hash, tmp_text, (KEY_SIZE + BLOCK_SIZE) * 8);
		copy_block(tmp_hash, keys->key0, 0, 0, KEY_SIZE);
	}
}
