#include "crypto.h"
#include "uart.h"
#include "aes.h"

#include <stdbool.h>
#include <stdio.h>
#include <avr/pgmspace.h>
#include <avr/boot.h>
#include <avr/interrupt.h>
#include <avr/wdt.h>

/* Assumes the buffer length is 16 bytes */ 
void decrypt(uint8_t *enc_data, uint8_t* dec_data)

/* Assumes the buffer's length is 16 bytes */
void encrypt(uint8_t *dec_data, uint8_t* enc_data)
