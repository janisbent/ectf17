#include "crypto.h"
#include "uart.h"
#include "aes.h"

#include <stdbool.h>
#include <stdio.h>
#include <avr/pgmspace.h>
#include <avr/boot.h>
#include <avr/interrupt.h>
#include <avr/wdt.h>

#define BUFF_LEN 16
const unsigned char KEY[] = "1234567890123456";

/* Assumes the buffer's length is 16 bytes */ 
void decrypt(uint8_t *enc_data, uint8_t *dec_data)
{
    /* Debugging */ 
    for (int i = 0; i < BUFF_LEN; i++) {
        UART1_putchar(enc_data[i]);
    }

    AES128_ECB_decrypt(enc_data, KEY, dec_data);

    /* Debugging */
    for (int i = 0; i < BUFF_LEN; i++) {
        UART1_putchar(dec_data[i]);
    }
}

/* Assumes the buffer's length is 16 bytes */
void encrypt(uint8_t *dec_data, uint8_t *enc_data),
{

    /* Debugging */
    for (int i = 0; i < BUFF_LEN; i++) {
        UART1_putchar(dec_data[i]);
    }

    AES128_ECB_encrypt(dec_data, KEY, enc_data); 

    /* Debugging */
    for (int i = 0; i < BUFF_LEN; i++) {
        UART1_putchar(enc_data[i]);
    }
}
