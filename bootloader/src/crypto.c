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
const unsigned char KEY[] EEMEM = "1234567890123456\0";
// const unsigned char KEY[] = AES_KEY;

/* Assumes the buffer's length is 16 bytes */ 
void decrypt(uint8_t *enc_data, uint8_t *dec_data)
{
    /* Debugging */ 
    UART1_putchar(0x69);
    for (int i = 0; i < BUFF_LEN; i++) {
        UART1_putchar(enc_data[i]);
    }

    AES128_ECB_decrypt(enc_data, KEY, dec_data);

    UART1_putchar(0x47);
    /* Debugging */
    for (int i = 0; i < BUFF_LEN; i++) {
        UART1_putchar(dec_data[i]);
    }
}

/* Assumes the buffer's length is 16 bytes */
void encrypt(uint8_t *dec_data, uint8_t *enc_data)
{

    uint8_t key[17];

    for (int i = 0; i < 17; i++) {
        key[i] = eeprom_read_byte(&(KEY[i]));
    }

    //UART1_putchar(0x11);
    //UART1_putchar(0x11);
    //UART1_putchar(0x11);
    /* Debugging */

    UART1_putchar(0xaa);
    UART1_putchar(0xaa);
    UART1_putchar(0xaa);

    //UART1_putstring(key);
    for (int i = 0; i < BUFF_LEN; i++) {
        UART1_putchar(dec_data[i]);
        wdt_reset();
    }

    UART1_putchar(0xbb);
    UART1_putchar(0xbb);
    UART1_putchar(0xbb);

    for (int i = 0; i < BUFF_LEN; i++) {
        UART1_putchar(enc_data[i]);
        wdt_reset();
    }

    AES128_ECB_encrypt(dec_data, key, enc_data); 
    wdt_reset();

    UART1_putchar(0xee);
    UART1_putchar(0xee);
    UART1_putchar(0xee);

    /* Debugging */
    for (int i = 0; i < BUFF_LEN; i++) {
        UART1_putchar(enc_data[i]);
        wdt_reset();
    }

    UART1_putchar(0xff);
    UART1_putchar(0xff);
    UART1_putchar(0xff);
    while (1) {
        continue;
    }
}
