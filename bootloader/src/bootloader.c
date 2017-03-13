/*
 * bootloader.c
 *
 * If Port B Pin 2 (PB2 on the protostack board) is pulled to ground the 
 * bootloader will wait for data to appear on UART1 (which will be interpretted
 * as an updated firmware package).
 * 
 * If the PB2 pin is NOT pulled to ground, but 
 * Port B Pin 3 (PB3 on the protostack board) is pulled to ground, then the 
 * bootloader will enter flash memory readback mode. 
 * 
 * If NEITHER of these pins are pulled to ground, then the bootloader will 
 * execute the application from flash.
 *
 * If data is sent on UART for an update, the bootloader will expect that data 
 * to be sent in frames. A frame consists of two sections:
 * 1. Two bytes for the length of the data section
 * 2. A data section of length defined in the length section
 *
 * [ 0x02 ]  [ variable ]
 * ----------------------
 * |  Length |  Data... |
 *
 * Frames are stored in an intermediate buffer until a complete page has been
 * sent, at which point the page is written to flash. See program_flash() for
 * information on the process of programming the flash memory. Note that if no
 * frame is received after 2 seconds, the bootloader will time out and reset.
 *
 */

#include <avr/io.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <util/delay.h>
#include <avr/boot.h>
#include <avr/wdt.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#include <stdbool.h>

#include "uart.h"
#include "aes.h"
#include "keys.h"

#define OK    ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define IV_SIZE 16

void program_flash(uint32_t page_address, unsigned char *data);
void load_firmware(void);
void boot_firmware(void);
void readback(void);
void read_frame(unsigned char *data, unsigned char *key);
void compare_nonces(unsigned char *data);
void get_key(unsigned char *key);
void generate_iv(uint8_t *iv, uint32_t seed, bool seed_rng);

uint16_t fw_size EEMEM = 0;
uint16_t fw_version EEMEM = 0;

int main(void)
{
    // Init UART1 (virtual com port)
    UART1_init();

    UART0_init();
    wdt_reset();

    // Configure Port B Pins 2 and 3 as inputs.
    DDRB &= ~((1 << PB2) | (1 << PB3));

    // Enable pullups - give port time to settle.
    PORTB |= (1 << PB2) | (1 << PB3);

    // If jumper is present on pin 2, load new firmware.
    if(!(PINB & (1 << PB2)))
    {
        UART1_putchar('U');
        load_firmware();
    }
    else if(!(PINB & (1 << PB3)))
    {
        UART1_putchar('R');
        readback();
    }
    else
    {
        UART1_putchar('B');
        boot_firmware();
    }
} // main

/***********************************************
 **************** BOOT FIRMWARE ****************
 ***********************************************/

void boot_firmware(void)
{
    // Start the Watchdog Timer.
    wdt_enable(WDTO_2S);

    // Write out the release message.
    uint8_t cur_byte;
    uint32_t addr = (uint32_t)eeprom_read_word(&fw_size);

    // Reset if firmware size is 0 (indicates no firmware is loaded).
    if(addr == 0)
    {
        // Wait for watchdog timer to reset.
        while(1) __asm__ __volatile__("");
    }

    wdt_reset();

    // Write out release message to UART0.
    do
    {
        cur_byte = pgm_read_byte_far(addr);
        UART0_putchar(cur_byte);
        ++addr;
    } while (cur_byte != 0);

    // Stop the Watchdog Timer.
    wdt_reset();
    wdt_disable();

    /* Make the leap of faith. */
    asm ("jmp 0000");
}

/***********************************************
 ****************** READBACK *******************
 ***********************************************/

void readback(void)
{
    uint8_t frame[SPM_PAGESIZE];
    uint8_t output[SPM_PAGESIZE];
    uint8_t key[IV_SIZE];
    uint8_t iv[IV_SIZE];
    uint32_t addr;
    uint32_t start_addr;
    uint32_t size;
	uint32_t seed;

    // Start the Watchdog Timer
    wdt_enable(WDTO_2S);

    get_key(key);
    read_frame(frame, key);

    compare_nonces(frame);

    // Read in start address (4 bytes).
    start_addr  = ((uint32_t)frame[4]) << 24;
    start_addr |= ((uint32_t)frame[5]) << 16;
    start_addr |= ((uint32_t)frame[6]) << 8;
    start_addr |= ((uint32_t)frame[7]);
    addr = start_addr;

    wdt_reset();

    // Read in size (4 bytes).
    size  = ((uint32_t)frame[8]) << 24;
    size |= ((uint32_t)frame[9]) << 16;
    size |= ((uint32_t)frame[10]) << 8;
    size |= ((uint32_t)frame[11]);

    wdt_reset();

    // Read in seed (4 bytes).
    seed  = ((uint32_t)frame[12]) << 24;
    seed |= ((uint32_t)frame[13]) << 16;
    seed |= ((uint32_t)frame[14]) << 8;
    seed |= ((uint32_t)frame[15]);

	generate_iv(iv, seed, true);

    // Read the memory out to UART1.
    while (addr < start_addr + size)
    {
        for (int i = 0; i < SPM_PAGESIZE; i++) {
            frame[i] = pgm_read_byte_far(addr++);
            wdt_reset();
        }

		generate_iv(iv, 0, false);

        AES128_CBC_encrypt_buffer(output, frame, SPM_PAGESIZE, key, iv);

        // Write the byte to UART1.
        for (int i = 0; i < SPM_PAGESIZE; i++) {
            UART1_putchar(output[i]);
            wdt_reset();
        }
    }

    while(1) __asm__ __volatile__(""); // Wait for watchdog timer to reset.
}

void compare_nonces(unsigned char *data)
{
    uint32_t nonce = 0;
    uint32_t nonce_val = 0;

    // Get nonces
    for (int i = 0; i < 4; i++) {
        nonce |= ((uint32_t)data[i]) << (24 - i * 8);
        nonce_val <<= 8;
        nonce_val |= (uint32_t)eeprom_read_byte(&NONCE[i]);
    }

    // Compare nonces
    if (nonce != nonce_val) {
        UART1_putchar(ERROR); // Reject the metadata.
        while(1) {
            __asm__ __volatile__("");
        }
    } else {
        UART1_putchar(OK);
    }
}

void generate_iv(uint8_t *iv, uint32_t seed, bool seed_rng)
{
	if (seed_rng) {
		srand(seed);
	}

	for (int i = 0; i < IV_SIZE; i++) {
		iv[i] = (uint8_t)rand();
	}
}

void get_key(unsigned char *key)
{
    for (int i = 0; i < IV_SIZE; i++) {
        key[i] = eeprom_read_byte(&KEY[i]);
    }
}

void read_frame(unsigned char *data, unsigned char *key)
{
    int frame_length = 0;
    unsigned char rcv = 0;
	unsigned char iv[IV_SIZE];
    unsigned char page[SPM_PAGESIZE];
    unsigned char output[SPM_PAGESIZE];

    // Get two bytes for the length.
    rcv = UART1_getchar();
    frame_length = (int)rcv << 8;
    rcv = UART1_getchar();
    frame_length += (int)rcv;
	frame_length -= IV_SIZE;

    wdt_reset();
    
	for (int i = 0; i < IV_SIZE; i++) {
		iv[i] = UART1_getchar();
	}

    // Get the number of bytes specified
    for (int i = 0; i < frame_length; ++i) {
        wdt_reset();
        page[i] = UART1_getchar();
    }

    // Decrypt frame
    AES128_CBC_decrypt_buffer(output, page, frame_length, key, iv);
    
    for(int i = 0; i < frame_length; ++i){
        wdt_reset();
        data[i] = output[i];
    }

    UART1_putchar(OK); // Acknowledge the frame.
}

/***********************************************
 **************** LOAD FIRMWARE ****************
 ***********************************************/

void load_firmware(void)
{
    unsigned char data[SPM_PAGESIZE]; // SPM_PAGESIZE is the size of a page.
    unsigned char key[IV_SIZE];
    unsigned int page = 0;
    uint16_t version = 0;
    uint16_t size = 0;

    // Start the Watchdog Timer
    wdt_enable(WDTO_2S);

    /* Wait for data */
    while(!UART1_data_available())
    {
        __asm__ __volatile__("");
    }

    get_key(key);
    read_frame(data, key);

    compare_nonces(data);

    // Get version.
    version  = ((uint16_t)data[4]) << 8;
    version |= ((uint16_t)data[5]);

    // Get size.
    size  = ((uint16_t)data[6]) << 8;
    size |= ((uint16_t)data[7]);

    // Compare to old version and abort if older (note special case for version
    // 0).
    if (version != 0 && version < eeprom_read_word(&fw_version))
    {
        UART1_putchar(ERROR); // Reject the metadata.
        // Wait for watchdog timer to reset.
        while(1)
        {
            __asm__ __volatile__("");
        }
    }
    else if(version != 0)
    {
        // Update version number in EEPROM.
        wdt_reset();
        eeprom_update_word(&fw_version, version);
    }

    // Write new firmware size to EEPROM.
    wdt_reset();
    eeprom_update_word(&fw_size, size);
    wdt_reset();

    /* Loop here until you can get all your characters and stuff */
    while (1)
    {
        wdt_reset();

        read_frame(data, key);

		wdt_reset();
		program_flash(page, data);
		page += SPM_PAGESIZE;
    } // while(1)
}




/*
 * To program flash, you need to access and program it in pages
 * On the atmega1284p, each page is 128 words, or 256 bytes
 *
 * Programing involves four things,
 * 1. Erasing the page
 * 2. Filling a page buffer
 * 3. Writing a page
 * 4. When you are done programming all of your pages, enable the flash
 *
 * You must fill the buffer one word at a time
 */
void program_flash(uint32_t page_address, unsigned char *data)
{
    int i = 0;
    boot_page_erase_safe(page_address);

    for(i = 0; i < SPM_PAGESIZE; i += 2)
    {
        uint16_t w = data[i];    // Make a word out of two bytes
        w += data[i+1] << 8;
        boot_page_fill_safe(page_address+i, w);
    }

    boot_page_write_safe(page_address);
    boot_rww_enable_safe(); // We can just enable it after every program too
}
