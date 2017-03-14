/*
 * config.c
 */

#include <avr/eeprom.h>
#include <stdint.h>
#include "sha1.h"
#include "crypto.h"
#include "config.h"

/* Load the secret parameters from the EEPROM */
void config_init(crypt_keys_t *keys) {
	// Read the key and seed from EEPROM
	for (uint8_t i = 0; i < KEY_SIZE; i++) {
		keys->key[i] = eeprom_read_byte((uint8_t*) (MKEY_ADDR + i));
	}
	for (uint8_t i = 0; i < SHA1_HASH_BYTES; i++) {
		keys->rand[i] = eeprom_read_byte((uint8_t*) (SEED_ADDR + i));
	}
}

/* Load the updated seed into the EEPROM */
void config_update_seed(crypt_keys_t *keys) {
	for (uint8_t i = 0; i < SHA1_HASH_BYTES; i++) {
		eeprom_update_byte((uint8_t*) (SEED_ADDR + i), keys->rand[i]);
	}
}
