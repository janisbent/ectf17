/*
 * config.h
 */

#ifndef CONFIG_H_
#define CONFIG_H_


/* Constants */
#define _AVR_
#define MKEY_ADDR 40
#define SEED_ADDR 80
#define DEC_CONST 0x44454343


/* Prototypes */
void config_init(crypt_keys_t*);
void config_update_seed(crypt_keys_t*);


#endif /* CONFIG_H_ */
