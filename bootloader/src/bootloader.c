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

/* TODO TODO TODO TODO TODO TODO TODO
 * 
 * set lockbits programatically
 * fix file comments
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
#define ABORT ((unsigned char)0xff)
#define HEADER_SIZE sizeof(Header_data)

uint16_t fw_size EEMEM = 0;
uint16_t fw_version EEMEM = 0;

typedef struct Header_data {
    uint16_t version;
    uint16_t body_size;
    uint16_t message_size;
    bool passed;
} Header_data;

void boot_firmware(void);

void readback(void);
void read_mem(uint32_t start_addr, uint32_t size);
void write_frame(unsigned char frame[]);

void load_firmware(void);
void program_flash(uint32_t page_address, unsigned char *data);
unsigned int read_frame(unsigned char buffer[], unsigned int buffer_index,
                        int retries);
Header_data check_header(void);
Header_data read_header(void);
void store_body(Header_data h);
void advance_buffer(unsigned char buffer[], unsigned int buffer_index);

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


/***************************************************
 ***************** BOOT FIRMWARE *******************
 ***************************************************/

void boot_firmware(void)
{
    // Start the Watchdog Timer.
    wdt_enable(WDTO_2S);

    // Write out the release message.
    uint8_t cur_byte;
    uint32_t message_addr = (uint32_t)eeprom_read_word(&fw_size);

    // Reset if firmware size is 0 (indicates no firmware is loaded).
    if(message_addr == 0)
    {
        // Wait for watchdog timer to reset.
        while(1) __asm__ __volatile__("");
    }

    wdt_reset();

    // Write out release message to UART0.
    do
    {
        cur_byte = pgm_read_byte_far(message_addr);
        UART0_putchar(cur_byte);
        ++message_addr;
    } while (cur_byte != 0);

    // Stop the Watchdog Timer.
    wdt_reset();
    wdt_disable();

    /* Make the leap of faith. */
    asm ("jmp 0000");
}


/***************************************************
 ******************** READBACK *********************
 ***************************************************/

void readback(void)
{
    unsigned char frame[FRAME_SIZE];
    unsigned int frame_index = 0;
    uint32_t start_addr = 0;
    uint32_t size = 0;

    // Start the Watchdog Timer
    wdt_enable(WDTO_2S);

    // Read frame from UART1
    while (read_frame(frame, frame_index, 0) < 0) ;

    // Read in start address (4 bytes).
    start_addr  = ((uint32_t)frame[frame_index++]) << 24;
    start_addr |= ((uint32_t)frame[frame_index++]) << 16;
    start_addr |= ((uint32_t)frame[frame_index++]) << 8;
    start_addr |= ((uint32_t)frame[frame_index++]);
    wdt_reset();

    // Read in size (4 bytes).
    size  = ((uint32_t)frame[frame_index++]) << 24;
    size |= ((uint32_t)frame[frame_index++]) << 16;
    size |= ((uint32_t)frame[frame_index++]) << 8;
    size |= ((uint32_t)frame[frame_index++]);
    wdt_reset();

    // Read the memory out to UART1.

    // Wait for watchdog timer to reset.
    while(1) __asm__ __volatile__("");
}

void read_mem(uint32_t start_addr, uint32_t size)
{
    unsigned char frame[FRAME_SIZE];
    unsigned char buffer[SPM_PAGESIZE];
    unsigned int buffer_index = 0;
    uint32_t addr = start_addr;

    while (addr < start_addr + size)
    {
        // Fill page from memory
        for (buffer_index = 0; buffer_index < SPM_PAGESIZE 
                               && addr < start_addr + size; addr++)
        {
            buffer[buffer_index++] = pgm_read_byte_far(addr);
            wdt_reset();
        }

        // Encrypt page of data
        encrypt_frame(frame, buffer, buffer_index);
        wdt_reset();

        // Write frame to UART1
        write_frame(frame);
        wdt_reset();
    }
}

void write_frame(unsigned char frame[])
{
    do
    {
        // write frame to UART1
        for (int frame_index = 0; frame_index < FRAME_SIZE; frame_index++)
        {
            UART1_putchar(frame[frame_index]);
        }
        wdt_reset();
    } while (UART1_getchar() == ERROR); // resend frame if rejected
}

/***************************************************
 ***************** LOAD FIRMWARE *******************
 ***************************************************/

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

    // Get header data
    h.passed = false;
    do
    {
        h = check_header();
    } while (!h.passed);

    // Write new firmware sizes to EEPROM.
    wdt_reset();
    eeprom_update_word(&fw_size, h.body_size);
    wdt_reset();

    // Get and store body data
    store_body(h);
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

/*
 * Reads one 512B frame of data from UART1, retrying up to retries times 
 * if verification fails and aborting after.
 *
 * Fills data into the buffer starting at buffer[buffer_index]
 */
unsigned int read_frame(unsigned char buffer[], unsigned int buffer_index, 
                int retries)
{
    unsigned char frame[FRAME_SIZE];
    unsigned int size = 0;

retry_frame:
    for (unsigned int data_index = 0; data_index < FRAME_SIZE; data_index++)
    {
        frame[data_index] = UART1_getchar();
        wdt_reset();
    }

    size = decrypt_frame(frame, buffer, buffer_index);

    // return if decryption succeeds
    if (size > 0)
    {
        UART1_putchar(OK); // Acknowledge the frame.
        return size;
    }

    // if frame retries requested
    if (retries-- > 0) 
    {
        UART1_putchar(ERROR);   // report rejected frame
        goto retry_frame;       // reread frame
    }

    // abort with error
    UART1_putchar(ABORT);
    while(1) __asm__ __volatile__("");

    // Silence compiler
    return 0;
}

Header_data check_header(void)
{
    Header_data h;
    
    // get header data
    h = read_header();
    wdt_reset();

    // Pass if higher version or version 0 
    if (h.version == 0 || h.version < eeprom_read_word(&fw_version)) 
    {
        goto version_pass;
    }

    // Reject the metadata
    UART1_putchar(ABORT);

    // Wait for watchdog timer to reset.
    while (1) __asm__ __volatile__("");
   
version_pass:
    if (h.version != 0)
    {
        // Update version number in EEPROM.
        wdt_reset();
        eeprom_update_word(&fw_version, h.version);
    }

    h.passed = true;

    return h;
}

Header_data read_header(void)
{
    unsigned char buffer[FRAME_SIZE];
    unsigned int buffer_index = 0;
    Header_data h;

    read_frame(buffer, buffer_index, 0);

    // parse decrypted header data to variables
    for ( ; buffer_index < HEADER_SIZE; buffer_index += 2) {
        switch (buffer_index) {
            case 0 : h.version = (uint16_t)buffer[buffer_index] << 8;
                     h.version += buffer[buffer_index + 1];
                     break;
            case 2 : h.body_size = (uint16_t)buffer[buffer_index] << 8;
                     h.body_size += buffer[buffer_index + 1];
                     break;
            case 4 : h.message_size = (uint16_t)buffer[buffer_index] << 8;
                     h.message_size += buffer[buffer_index + 1];
                     break;
        }
        wdt_reset();
    }

    return h;
}

void store_body(Header_data h)
{
    unsigned char buffer[FRAME_SIZE * 3];
    unsigned int buffer_index = 0;
    unsigned int page = 0;
    unsigned int size = 0;
    unsigned int package_size = h.message_size + h.body_size;

    for (unsigned int bytes_read = 0; bytes_read < package_size; 
         bytes_read += size)
    {
        // Recieve one body frame 
        size = read_frame(buffer, buffer_index, 3);
        wdt_reset();
        
        buffer_index += size;

        // Write full pages to buffer
        while (buffer_index > SPM_PAGESIZE)
        {
            // Program page to memory
            program_flash(page, buffer);
            wdt_reset();

            // Move unwritten data up in buffer
            advance_buffer(buffer, buffer_index);
            wdt_reset();

            // Remove page from buffer index and add to page
            buffer_index -= SPM_PAGESIZE;
            page += SPM_PAGESIZE;
        }

#if 1
        // Write debugging messages to UART0.
        UART0_putchar('P');
        UART0_putchar(page>>8);
        UART0_putchar(page);
        wdt_reset();
#endif

        wdt_reset();
    }

    // write last page to memory
    program_flash(page, buffer);
}

/*
 * Moves every element in the buffer up a page and 0s memory of old location
 */
void advance_buffer(unsigned char buffer[], unsigned int buffer_index)
{
    for (unsigned i = 0; i + SPM_PAGESIZE < buffer_index; i++)
    {
        buffer[i] = buffer[i + SPM_PAGESIZE];
        buffer[i + SPM_PAGESIZE] = 0;
    }
}
