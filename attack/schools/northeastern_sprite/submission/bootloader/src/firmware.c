/*
 * firmware.c
 */

#include <stdint.h>
#include <stdbool.h>
#include "sha1.h"
#include "crypto.h"
#include "message.h"
#include "config.h"
#include "readback.h"  // Uses helper functions from readback

/* Load the constant from the first decrypted frame */
uint32_t fw_load_constant(const uint8_t *msg) {
	return extract_uint32_t(msg, 0);
}

/* Load the number of frames from the first decrypted frame */
uint32_t fw_load_num_frames(const uint8_t *msg) {
	return extract_uint32_t(msg, 4);
}

/* Load the firmware version from the first decrypted frame */
uint32_t fw_load_version(const uint8_t *msg) {
	return extract_uint32_t(msg, 8);
}

/* Load the firmware size from the first decrypted frame */
uint32_t fw_load_fw_size(const uint8_t *msg) {
	return extract_uint32_t(msg, 12);
}

/* Decrypt the message that was sent and verify that the hash of the message equals the sent hash */
bool fw_decrypt_and_integrity(const uint8_t *encrypted, uint8_t *decrypted, const uint8_t *hash, crypt_keys_t *keys, uint8_t len) {
	uint8_t self_hash[SHA1_HASH_BYTES];

	// Decrypt the message first
	crypt_decrypt(encrypted, decrypted, keys, len);

	// Verify that the hash of decrypted text matches sent hash
	sha1(self_hash, decrypted, len * 8);
	bool result = compare_blocks(self_hash, hash, KEY_SIZE);

	return result;
}
