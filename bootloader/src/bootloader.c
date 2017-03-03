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
#include <util/delay.h>
#include <avr/boot.h>
#include <avr/wdt.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>

#include "uart.h"
#include "aes.h"

#define OK    ((unsigned char)0x00)
#define ERROR ((unsigned char)0xFF)

void program_flash(uint32_t page_address, unsigned char *data);
void load_firmware(void);
void boot_firmware(void);
void readback(void);
void encryption_test();
int read_frame(unsigned char *data);
void send_frame(unsigned char *data);

uint16_t fw_size EEMEM = 0;
uint16_t fw_version EEMEM = 0;

unsigned char KEY[] EEMEM = "1234567890123456";

#define FRAME_SIZE 16

typedef struct header {
    uint16_t version;
    uint16_t fw_size;
    uint16_t msg_size;
} header;

int main(void)
{
    // Init UART1 (virtual com port)
    UART1_init();
    UART0_init();

    //wdt_reset();

    // Configure Port B Pins 2 and 3 as inputs.
    DDRB &= ~((1 << PB2) | (1 << PB3));

    // Enable pullups - give port time to settle.
    PORTB |= (1 << PB2) | (1 << PB3);

    UART1_putchar(0x66);
    UART1_putchar(0x66);
    UART1_putchar(0x66);
    UART1_putchar(0x66);
    UART1_putchar(0x66);
    UART1_putchar(0x66);

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

    //wdt_reset();

    // Write out release message to UART0.
    do
    {
        cur_byte = pgm_read_byte_far(addr);
        UART0_putchar(cur_byte);
        ++addr;
    } while (cur_byte != 0);

    // Stop the Watchdog Timer.
    //wdt_reset();
    wdt_disable();

    /* Make the leap of faith. */
    asm ("jmp 0000");
}

/***********************************************
 ****************** READBACK *******************
 ***********************************************/

void readback(void)
{
    unsigned char data[16];

    // Start the Watchdog Timer
    wdt_enable(WDTO_2S);

    // Read in header data
    read_frame(data);

    // Parse start address
    uint32_t start_addr = ((uint32_t)data[0]) << 24;
    start_addr |= ((uint32_t)data[1]) << 16;
    start_addr |= ((uint32_t)data[2]) << 8;
    start_addr |= ((uint32_t)data[3]);

    //wdt_reset();

    // Parse size
    uint32_t size = ((uint32_t)data[4]) << 24;
    size |= ((uint32_t)data[5]) << 16;
    size |= ((uint32_t)data[6]) << 8;
    size |= ((uint32_t)data[7]);

    //wdt_reset();

    // Read the memory out to UART1.
    for(uint32_t addr = start_addr; addr < start_addr + size; ++addr)
    {
        for (int i = 0; i < 16; i++) 
        {
            data[i] = pgm_read_byte_far(addr++);
        }
        
        //wdt_reset();

        send_frame(data);

        //wdt_reset();
    }

    while(1) __asm__ __volatile__(""); // Wait for watchdog timer to reset.
}

int read_frame(unsigned char *data)
{
    int frame_len;
    unsigned char frame[16];
    uint8_t key[16];

    for (int i = 0; i < 16; i++) {
        key[i] = eeprom_read_byte(&(KEY[i]));
    }

    // Get two bytes for the length.
    //frame_len  = ((int)UART1_getchar()) << 8;
    //frame_len |= (int)UART1_getchar();
    
    for (int i = 0; i < FRAME_SIZE; i++) {
        frame[i] = UART1_getchar();
    }
    
    AES128_ECB_decrypt(frame, key, data);

    UART1_putchar(OK);

    return FRAME_SIZE;
}

void send_frame(unsigned char *data)
{
    unsigned char frame[16];
    uint8_t key[16];

    for (int i = 0; i < 16; i++) {
        key[i] = eeprom_read_byte(&(KEY[i]));
    }

    AES128_ECB_encrypt(data, key, frame); 

    for (int i = 0; i < 16; i++) {
        UART1_putchar(frame[i]);
    }
}

/***********************************************
 *************** UPDATE FIRMWARE ***************
 ***********************************************/

/*
 * Load the firmware into flash.
 */
void load_firmware(void)
{
    int frame_len = 0;
    unsigned char frame[FRAME_SIZE];
    unsigned char data[SPM_PAGESIZE]; // SPM_PAGESIZE is the size of a page.
    unsigned int data_index = 0;
    unsigned int page = 0;
    uint16_t version = 0;
    uint16_t fw_size = 0;
    uint16_t msg_size = 0;


    /* Wait for data */
    while(!UART1_data_available())
    {
        __asm__ __volatile__("");
    }

    // Start the Watchdog Timer
    // wdt_enable(WDTO_2S); //////////////////////////

    read_frame(frame);

    // Get firmware size.
    fw_size  = ((uint16_t)frame[0]) << 8;
    fw_size |= frame[1];

    // Get message size
    msg_size  = ((uint16_t)frame[2]);
    msg_size |= frame[3];

    // Get version.
    version  = ((uint16_t)frame[4]) << 8;
    version |= frame[5];

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
    else if (version != 0)
    {
        // Update version number in EEPROM.
        //wdt_reset();
        eeprom_update_word(&fw_version, version);
    }

    // Write new firmware size to EEPROM.
    //wdt_reset();
    eeprom_update_word(&fw_size, fw_size);
    //wdt_reset();

    /* Loop here until you can get all your characters and stuff */
    while (1)
    {
        //wdt_reset();
        
        frame_len = read_frame(frame);
    
        for (int i = 0; i < FRAME_SIZE; i++) 
        {
            data[data_index++] = frame[i];
        }
        
        // If we filed our page buffer, program it
        if(data_index >= SPM_PAGESIZE || frame_len == 0)
        {
            //wdt_reset();
            program_flash(page, data);
            page += SPM_PAGESIZE;
            data_index -= SPM_PAGESIZE;

            //wdt_reset();

        } // if
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
