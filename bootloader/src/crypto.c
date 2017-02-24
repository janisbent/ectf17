#include "crypto.h"
#include "uart.h"

#include <stdbool.h>
#include <stdio.h>
#include <avr/pgmspace.h>
#include <avr/boot.h>
#include <avr/interrupt.h>
#include <avr/wdt.h>

//const unsigned uint32_t nonce = 0x01234567;
const unsigned char KEY[] EEMEM = "Hello world!";
const unsigned int KEYSIZE = sizeof(KEY);

int decrypt_frame(unsigned char *frame, unsigned char *buffer, 
                  unsigned int buffer_start)
{
	/*uint8_t byte;

    for (unsigned int frame_index = 0; frame_index < FRAME_SIZE; frame_index++)
    {
        byte = frame[frame_index];

        byte ^= KEY[frame_index % KEYSIZE];

        buffer[frame_index + buffer_start] = byte;

        wdt_reset();
#if DEBUG
        UART1_putchar(byte);
#endif
    }*/
    for (int i = 0; i < FRAME_SIZE; i++) {
        buffer[i + buffer_start] = frame[i];
    }

    return FRAME_SIZE;
}


int encrypt_frame(unsigned char *frame, unsigned char *buffer,
                   unsigned int size)
{
  /*(uint8_t byte;

    for (unsigned int i = 0; i < size; i++)
    {
        byte = buffer[i];

        byte ^= KEY[i % KEYSIZE];

        frame[i] = byte;

        wdt_reset();
    }*/

    for (int i = 0; i < size; i++) {
        frame[i] = buffer[i];
    }

    return size;
}
