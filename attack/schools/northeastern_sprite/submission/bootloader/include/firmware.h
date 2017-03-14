/*
 * firmware.h
 */

#ifndef FIRMWARE_H_
#define FIRMWARE_H_


/* Prototypes */
uint32_t fw_load_constant(const uint8_t*);
uint32_t fw_load_num_frames(const uint8_t*);
uint32_t fw_load_version(const uint8_t*);
uint32_t fw_load_fw_size(const uint8_t*);
bool fw_decrypt_and_integrity(const uint8_t*, uint8_t*, const uint8_t*, crypt_keys_t*, uint8_t);


#endif /* FIRMWARE_H_ */
