/*
 * readback.h
 */

#ifndef READBACK_H_
#define READBACK_H_


/* Helping functions */
uint32_t extract_uint32_t(const uint8_t*, const uint8_t);
bool compare_blocks(const uint8_t*, const uint8_t*, const uint8_t);

/* Prototypes */
uint32_t rdb_load_addr(const UART_msg_t*);
uint32_t rdb_load_size(const UART_msg_t*);
void rdb_send_auth_random(crypt_keys_t*, UART_msg_t*);
bool rdb_verify_auth_hash(const UART_msg_t*, uint8_t*, const crypt_keys_t*);
void rdb_send_enc_data(const uint8_t*, UART_msg_t*, crypt_keys_t*, const uint8_t);


#endif /* READBACK_H_ */
