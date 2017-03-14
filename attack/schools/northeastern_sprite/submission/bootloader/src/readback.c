/*
 * readback.c
 */

#include <stdint.h>
#include <stdbool.h>
#include "sha1.h"
#include "crypto.h"
#include "message.h"
#include "config.h"

#if defined _AVR_
#include <avr/wdt.h>
#endif

/* Compare the contents of two blocks of data upto number of bytes specified */
bool compare_blocks(const uint8_t *block1, const uint8_t *block2, const uint8_t num_bytes) {
	for (uint8_t i = 0; i < num_bytes; i++) {
		if (block1[i] != block2[i]) {
			return false;
		}
		#if defined _AVR_
			wdt_reset();
		#endif
	}
	return true;
}

/* Extract the uint32 number from the array (at start index) */
uint32_t extract_uint32_t(const uint8_t *msg, const uint8_t start) {
	uint32_t result;

	result  = (uint32_t) msg[start] << 24;
	result += (uint32_t) msg[start+1] << 16;
	result += (uint32_t) msg[start+2] << 8;
	result += (uint32_t) msg[start+3];

	return result;
}

/* Load the start address from the first frame */
uint32_t rdb_load_addr(const UART_msg_t *umsg) {
	return extract_uint32_t(umsg->msg, 0);
}

/* Load the size from the first frame */
uint32_t rdb_load_size(const UART_msg_t *umsg) {
	return extract_uint32_t(umsg->msg, 4);
}

/* Update the random 16 byte number in keys struct and send to the receiver */
void rdb_send_auth_random(crypt_keys_t *keys, UART_msg_t *umsg) {
	// Update seed and generate temp random keys
	generate_random_keys(keys);

	// Copy the updated seed to messaging struct and send
	umsg->len = KEY_SIZE;
	copy_block(keys->rand, umsg->msg, 0, 0, umsg->len);
	send_message(umsg);
}

/* Compute the hash of random seed xored with key, and verify that it matches the received hash */
bool rdb_verify_auth_hash(const UART_msg_t *umsg, uint8_t *self_hash, const crypt_keys_t *keys) {
	uint8_t auth_hash[KEY_SIZE];
	uint8_t tmp_xor[KEY_SIZE];
	init_block(tmp_xor, KEY_SIZE);

	// Calculate the hash of the seed xored with all the temp keys
	xor_blocks(tmp_xor, keys->rand, tmp_xor, KEY_SIZE);
	for (uint8_t i = 0; i < TEMP_KEYS; i++) {
		xor_blocks(tmp_xor, keys->tmp_key[i], tmp_xor, KEY_SIZE);
	}
	sha1(self_hash, tmp_xor, KEY_SIZE * 8);

	// Compare calculated hash with the received hash and return the result
	copy_block(umsg->msg, auth_hash, 0, 0, KEY_SIZE);
	bool auth_result = compare_blocks(auth_hash, self_hash, KEY_SIZE);

	return auth_result;
}

/* Encrypt the data and send to the receiver */
void rdb_send_enc_data(const uint8_t *plain_text, UART_msg_t *umsg, crypt_keys_t *keys, const uint8_t len) {
	umsg->len = len;
	crypt_encrypt(plain_text, umsg->msg, keys, len);
	send_message(umsg);
}
