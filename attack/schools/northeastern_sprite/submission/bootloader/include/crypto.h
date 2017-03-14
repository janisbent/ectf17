/*
 * keys.h
 */

#ifndef KEYS_H_
#define KEYS_H_


/* Constants */
#define TEMP_KEYS 3
#define KEY_SIZE 16
#define BLOCK_SIZE 16
#define POLY_DEG KEY_SIZE
#define MULT_DEG (2 * POLY_DEG) - 1


/* Structures */
typedef struct {
	uint8_t rand[SHA1_HASH_BYTES];
	uint8_t key[KEY_SIZE];
	uint8_t tmp_key[TEMP_KEYS][KEY_SIZE];
	uint8_t key0[KEY_SIZE];
} crypt_keys_t;


/* Prototypes */
void init_block(uint8_t*, const uint8_t);
void copy_block(const uint8_t*, uint8_t*, const uint8_t, const uint8_t, const uint8_t);
void xor_blocks(const uint8_t*, const uint8_t*, uint8_t*, const uint8_t);

void generate_random_keys(crypt_keys_t*);
void generate_encryption_key(const uint8_t*, crypt_keys_t*);

void crypt_init(const uint8_t*, crypt_keys_t*);
void crypt_encrypt(const uint8_t*, uint8_t*, crypt_keys_t*, const uint8_t);
void crypt_decrypt(const uint8_t*, uint8_t*, crypt_keys_t*, const uint8_t);


#endif /* KEYS_H_ */
