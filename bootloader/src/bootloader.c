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
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <util/delay.h>
#include <avr/boot.h>
#include <avr/wdt.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>

#include "uart.h"
#include "crypto.h"

#define OK    ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define NONCE_SIZE sizeof(uint64_t)
#define FRAME_SIZE 512

typedef struct Header_data {
    uint64_t nonce;
    uint16_t version;
    uint16_t body_size;
    uint16_t message_size;
    bool     passed;
} Header_data;

void program_flash(uint32_t page_address, unsigned char *data);
void load_firmware(void);
void boot_firmware(void);
void readback(void);
void read_frame(unsigned char data[]);
Header_data check_header(void);
Header_data read_header(void);
void store_body(Header_data h);
bool nonce_check(unsigned char data[]);

uint16_t fw_size EEMEM = 0;
uint16_t fw_version EEMEM = 0;
uint16_t msg_start EEMEM = 0;
uint16_t msg_size EEMEM = 0;

const uint16_t HEADER_SIZE = 14;
const uint64_t NONCE = 0x552B46353935; // U+1F595


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

/*
 * Interface with host readback tool.
 */
void readback(void)
{
    // Start the Watchdog Timer
    wdt_enable(WDTO_2S);

    // Read in start address (4 bytes).
    uint32_t start_addr = ((uint32_t)UART1_getchar()) << 24;
    start_addr |= ((uint32_t)UART1_getchar()) << 16;
    start_addr |= ((uint32_t)UART1_getchar()) << 8;
    start_addr |= ((uint32_t)UART1_getchar());

    wdt_reset();

    // Read in size (4 bytes).
    uint32_t size = ((uint32_t)UART1_getchar()) << 24;
    size |= ((uint32_t)UART1_getchar()) << 16;
    size |= ((uint32_t)UART1_getchar()) << 8;
    size |= ((uint32_t)UART1_getchar());

    wdt_reset();

    // Read the memory out to UART1.
    for(uint32_t addr = start_addr; addr < start_addr + size; ++addr)
    {
        // Read a byte from flash.
        unsigned char byte = pgm_read_byte_far(addr);
        wdt_reset();

        // Write the byte to UART1.
        UART1_putchar(byte);
        wdt_reset();
    }

    while(1) __asm__ __volatile__(""); // Wait for watchdog timer to reset.
}


/*
 * Load the firmware into flash.
 */
void load_firmware(void)
{
    Header_data h;

    /* Wait for data */
    while(!UART1_data_available())
    {
        __asm__ __volatile__("");
    }

    // Start the Watchdog Timer
    wdt_enable(WDTO_2S);

    h.passed = false;
    do
    {
        h = check_header();
    } while (!h.passed);

    // Write new firmware sizes to EEPROM.
    wdt_reset();
    eeprom_update_word(&fw_size, h.body_size);
    eeprom_update_word(&msg_size, h.message_size);
    wdt_reset();

    // Get and store body data
    store_body(h);
}


/*
 * Ensure the firmware is loaded correctly and boot it up.
 */
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

void read_frame(unsigned char data[])
{
    for (unsigned int data_index; data_index < FRAME_SIZE; data_index++)
    {
        data[data_index] = UART1_getchar();
        wdt_reset();
    }
}

Header_data check_header(void)
{
    Header_data h;
    
    // get header data
    h.nonce = 0;
    h = read_header();
    wdt_reset();

    // Abort if invalid nonce
    while (h.nonce != NONCE)
    {
        __asm__ __volatile__("");
    }
    wdt_reset();

    // Compare to old version and abort if older (note special case for version
    // 0).
    if (h.version == 0 || h.version < eeprom_read_word(&fw_version))
    {
        goto version_pass;
    }

    // Reject the metadata
    UART1_putchar(ERROR);

    // Wait for watchdog timer to reset.
    while (1)
    {
        __asm__ __volatile__("");
    }
   
version_pass:
    if (h.version != 0)
    {
        // Update version number in EEPROM.
        wdt_reset();
        eeprom_update_word(&fw_version, version);
    }

    UART1_putchar(OK); // Acknowledge the metadata.

    return h;
}

Header_data read_header(void)
{
    unsigned char data[FRAME_SIZE];
    Header_data h;

    read_frame(data);
    decrypt_rsa(data);

    // parse decrypted header data to variables
    for (data_index = 0; data_index < HEADER_SIZE; data_index += 2) {
        switch (data_index) {
            case 0 : h.nonce =  (uint64_t)data[data_index] << 56;
                     h.nonce += (uint64_t)data[data_index + 1] << 48;
                     break;
            case 2 : h.nonce += (uint64_t)data[data_index] << 40;
                     h.nonce += (uint64_t)data[data_index + 1] << 32;
                     break;
            case 4 : h.nonce =  (uint64_t)data[data_index] << 24;
                     h.nonce += (uint64_t)data[data_index + 1] << 16;
                     break;
            case 6 : h.nonce += (uint64_t)data[data_index] << 8;
                     h.nonce += data[data_index + 1];
                     break;
            case 8 : h.version = (uint16_t)data[data_index] << 8;
                     h.version += data[data_index + 1];
                     break;
            case 10: h.body_size = (uint16_t)data[data_index] << 8;
                     h.body_size += data[data_index + 1];
                     break;
            case 12: h.message_size = (uint16_t)data[data_index] << 8;
                     h.message_size += data[data_index + 1];
                     break;
        }
        wdt_reset();
    }
}

void read_body(Header_data h)
{
    unsigned char data[FRAME_SIZE];
    unsigned int page = 0;
    bool on_message = false;
    bool passed = false;

    for ( ; page < h.body_size + h.message_size; page += SPM_PAGESIZE)
    {
retry_frame:
        // Recieve one body frame 
        read_frame(data);
        decrypt_rsa(data);
        wdt_reset();
        
        while (!passed) 
        {
            passed = nonce_check(data);

            if (!passed)
            {
                goto retry_frame;
            }
        }

        if (page >= h.body_size && !on_message)
        {
            on_message = true;
            eeprom_update_word(&msg_start, page);
        }

        // Write frame data to flash
        program_flash(page, data + NONCE_SIZE);
        wdt_reset();

#if 1
        // Write debugging messages to UART0.
        UART0_putchar('P');
        UART0_putchar(page>>8);
        UART0_putchar(page);
        wdt_reset();
#endif

        UART1_putchar(OK); // Acknowledge the frame.
        wdt_reset();
    }

}

bool nonce_check(unsigned char data[])
{
    uint64_t nonce = 0;
    static uint16_t nonce_fail = 3;
        
    // Get nonce
    for (int i = 0; i < NONCE_SIZE; i++) {
        nonce <<= 4;
        nonce += data[i];
    }
    wdt_reset();

    // Skip failure if nonce passes
    if (nonce == NONCE)
    {
        goto nonce_pass;
    }

    UART1_putchar(ERROR);

    // Ask for resend if attempts remain
    if (--nonce_fail > 0)
    {
        goto retry_frame;
    }
      
    // Abort if invalid nonce
    while (nonce != NONCE)
    {
        __asm__ __volatile__("");
    }

nonce_pass:
    nonce_fail = 3; // Reset nonce fail attempts
    wdt_reset();
}
