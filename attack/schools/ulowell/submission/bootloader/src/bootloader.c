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
 * If data is sent on UART for an readback, the bootloader will expect that data
 * to be sent in frames. A frame consists of four sections:
 * 1. One byte for the length of the password.
 * 2. The variable-length password.
 * 3. Four bytes for the start address.
 * 4. Four bytes for the number of bytes to read.
 *
 * [ 0x01 ]  [ variable ]  [ 0x04 ]    [ 0x04 ]
 * -------------------------------------------------
 * | PW Length | Password | Start Addr | Num Bytes |
 * -------------------------------------------------
 *
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
#include "uart.h"
#include "aes.h"
#include "sha1.h"
#include <avr/boot.h>
#include <avr/wdt.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>

#define OK    ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)

void program_flash(uint32_t page_address, unsigned char *data);

uint16_t fw_size EEMEM = 0;
uint16_t fw_version EEMEM = 0;

// GCC Compiler input password
static const uint8_t __attribute__ ((__progmem__)) p[] = RB_PASSWORD;
// GCC Compiler input AES key
static uint8_t EEMEM aes[] = AES;

// Generate 16 bytes AES key from GCC Compiler flags -DAES
void hextoraw(const uint8_t *aes, uint8_t * aeskey);
void printHexChar(uint8_t input);

// Boot function Message
static const uint8_t release_msg[4] PROGMEM = "Msg:";
static const uint8_t current_version[6] PROGMEM = ". Ver:";

int main(void)
{
    // Init UART1 (virtual com port)
    UART1_init();
    // Init UART0 (virtual com port)
    UART0_init();
    wdt_reset();

    // Configure Port B Pins 2 and 3 as inputs.
    DDRB &= ~((1 << PB2) | (1 << PB3));

    // Enable pullups - give port time to settle.
    PORTB |= (1 << PB2) | (1 << PB3);
	
	/*
	 * In bootloader main function, it has three mode: load_firmware, boot and readback
	 * Jumper setting will influence the bootloader executing mode.
	 * If jumper is present on pin 2, load bootloader mode
	 * If jumper is present on pin 3, readbackmode
	 * If no jumper, boot bootloader mode
     */	 

    if(!(PINB & (1 << PB2))) // If jumper is present on pin 2, load new firmware.
    {
        /*
         * Load the firmware into flash.
         */
        // load_firmware() mode, PB2 connect to Ground;
        int frame_length = 0;
        unsigned char rcv = 0;
        unsigned char data[SPM_PAGESIZE]; // SPM_PAGESIZE is the size of a page.
        unsigned int data_index = 0;
        unsigned int page = 0;
        uint16_t version = 0;
        uint16_t size = 0;
        uint16_t msg_length = 0;
        
        // AES decrypt parameters
        static uint8_t tmp[16];
        static uint8_t decrypt[16];
        static uint8_t key[16];
        unsigned char data_decrypt[SPM_PAGESIZE];
        
        // SHA1 Hash parameters
        uint32_t h[5];
        static uint8_t t[64];
        static uint8_t check[40];
        static uint8_t digest[20];
        static uint8_t fid[20];
        static uint8_t checksum[20];
        static uint16_t hash_index = 0;

        UART1_putchar('U');
        
        // Start the Watchdog Timer
        wdt_enable(WDTO_2S);
        // UART0_putchar('l');
            
        /* Wait for data */
        while(!UART1_data_available())
        {
            __asm__ __volatile__("");
        }
            
        // Get version.
        rcv = UART1_getchar();
        version = (uint16_t)rcv << 8;
        check[0] = version;
        rcv = UART1_getchar();
        version |= (uint16_t)rcv;
        check[1] = version;
        
        // Get size.
        rcv = UART1_getchar();
        size = (uint16_t)rcv << 8;
        check[2] = rcv;
        rcv = UART1_getchar();
        size |= (uint16_t)rcv;
        check[3] = rcv;
        
        // Get Firmware ID hash value
        wdt_reset();
        for(int i = 0; i < 20; ++i)
        {
            rcv = UART1_getchar();
            fid[i] = rcv;
            check[i + 4] = rcv;
        }
        
        // Get Firmware checksum
        wdt_reset();
        for(int i = 0; i < 20; ++i)
        {
            rcv = UART1_getchar();
            checksum[i] = rcv;
        }
        
        // Get AES key from eeprom
        wdt_reset();
        hextoraw(aes, key);
        for(int i = 0; i < 16; ++i){
            check[i+24] = key[i];
        }
        // Hash the input firmware information with AES key: sha1.hash(version || firmware_size || FirmwareID || AESKey)
        wdt_reset();
        sha1_init(h);                  // Initial the sha1 hash value
        pad_msg(check, t, 40, 40);     // Padding the hash block size to a multiple of 64 bytes
        sha1_loop(h, t);               // Sha1 hash the data block 
        gen_digest(h, digest);         // Generate the finial sha1 hash value
        
		wdt_reset();
		// Checking the input firmware information integrity with input checksum
		// Attacker doesn't have AES key, so any change can be detected in this checking
        for(int i = 0 ; i < 20; ++i){
            if(checksum[i] != digest[i])
            {
                UART1_putchar(ERROR); // Reject the metadata.
                // Wait for watchdog timer to reset.
                while(1)
                {
                    __asm__ __volatile__("");
                }
            }
        }
        
        // Pass Checksum checking, then check version number and update in EEPROM
        // Compare to old version and abort if older (note special case for version 0).
        wdt_reset();
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
        size = (size + 15) / 16 * 16;
        eeprom_update_word(&fw_size, size);
        wdt_reset();
    
        // SHA1 initial and perpare for reading firmware
        sha1_init(h);
        wdt_reset();
        UART1_putchar(OK); // Acknowledge the metadata.
        
        // Reading firmware
        /* Loop here until you can get all your characters and stuff */
        while (1)
        {
            // Get two bytes for the length.
            wdt_reset();
            rcv = UART1_getchar();
            frame_length = (int)rcv << 8;
            rcv = UART1_getchar();
            frame_length += (int)rcv;
                
            // Get the number of bytes specified
            wdt_reset();
            for(int i = 0; i < frame_length; ++i){
                wdt_reset();
                data[data_index] = UART1_getchar();
                data_index += 1;
                hash_index += 1;
            } //for
                
            // If we filed our hash block buffer or it is the last frame
            // Hash the encrypted firmware || release message
            // Here we use sha1 hash function.
            if( hash_index % 64 == 0 || frame_length == 0)
            {
                wdt_reset();
                
                // Prepare for SHA1 hashing.
                // Put the (encrypted firmware || release message) into tmp Hash block
                if(frame_length == 0) // If it is the last frame, padding the data into tmp hash block buffer
                {
                    if(hash_index > 55){
                        int i;
                        for(i = 0; i < hash_index; ++i)
                            t[i] = data[data_index-hash_index + i];
                        t[i] = 0x80;
                        i = i+1;
                        while(i < 64){
                            t[i] = 0x00;
                            i=i+1;
                        }
                        sha1_loop(h, t);
                        pad_msg(data, t, 0, page+data_index);
                    }
                    else if(hash_index == 64){
                        for(int i = 0; i < hash_index; ++i)
                            t[i] = data[data_index-hash_index + i];
                        sha1_loop(h, t);
                        pad_msg(data, t, 0, page+data_index);
                        t[0] = 0x80;
                    }
                    else
                    {
                        pad_msg(data+(data_index-hash_index), t, hash_index, page+data_index);
                    }
                }
                else            // Copy full 64 bytes data into tmp hash block buffer
                {
                    for(int i = 0; i < 64; ++i)
                        t[i] = data[data_index-hash_index + i];

                }
                
                // Calculate the sha1 hash value
                sha1_loop(h, t);
                hash_index = 0;
            }
                
            // AES decrypt firmware
            /* 
             * Each encrypted firmware has 16 bytes data.
             * size: encrypted firmware size
             * data_decrypt: the output data block. Should have decrypted firmware and release message
             * If page + data_index <= size, the input frame should be encrypted firmware
             *     AES decrypt the frame and save into the output data block
             * If page + data_index > size, the input frame should be release message
             *     Directly save into the output data block
             */
            if(page + data_index <= size)  //If it is the last frame of encrypted firmware
            {
                wdt_reset();
                for(int i = 0; i < frame_length; ++i)
                    tmp[i] = data[data_index - 16 + i];
                    
                AES128_ECB_decrypt(tmp, key, decrypt);
                    
                for(int i = 0; i < frame_length; ++i)
                    data_decrypt[i + data_index - 16] = decrypt[i];
            }
            else                           //Get the release message and put it directly into output data
            {
                wdt_reset();
                for(int i = 0; i < frame_length; ++i)
                    data_decrypt[i + data_index - frame_length] = data[ data_index - frame_length + i];
                
                //Check if release message bigger than 1kB
                msg_length += frame_length;
                if (msg_length > 1000)
                {
                    UART1_putchar(ERROR);   // Reject the firmware update process. Release message size too long.
                    // Wait for watchdog timer to reset.
                    while(1)
                    {
                        __asm__ __volatile__("");
                    }
                }
            }
                
            // If decrypt firmware date filed our page buffer, program it
            if(data_index == SPM_PAGESIZE || frame_length == 0)
            {
                wdt_reset();
                program_flash(page, data_decrypt);
                page += SPM_PAGESIZE;
                data_index = 0;
#if 0
                // Write debugging messages to UART0.
                UART0_putchar('P');
                UART0_putchar(page>>8);
                UART0_putchar(page);
#endif
                wdt_reset();
                    
            } // if
            
            if(frame_length == 0) //If last frame
                break;
            
            UART1_putchar(OK);    // Acknowledge the frame.
        }// while(1)
        
        // Calculate (encryptd firmware || release message) sha1 hash value
        // Check the firmware and release message integrity
        gen_digest(h, digest);
        
        // Compare digest with fid
        for(int i = 0; i < 20; ++i){
            if(fid[i] != digest[i]){
                UART1_putchar(ERROR);           // Reject the firmware update and erase the flash program memory.
                while(page != 0){
                    page -= SPM_PAGESIZE;
                    boot_page_erase_safe(page); // Erase all programed flash memory
                }
                while(1)
                {
                    __asm__ __volatile__("");
                }
            }
        }
        
        UART1_putchar(OK);                  // Acknowledge the frame.
        while(1) __asm__ __volatile__("");  // Wait for watchdog timer to reset.
    }
    else if(!(PINB & (1 << PB3))) // If jumper is present on pin 3, readback firmware.
    {
        /*
         * Interface with host readback tool.
         */
        // readback() mode, PB3 connect to Ground;
        uint16_t p_length;
        unsigned char rcv = 0;
        
        // AES encrypt parameters
        static uint8_t key[16];
        static uint8_t tmp[16];
        static uint8_t en[16];
        
        UART1_putchar('R');
        
        // Start the Watchdog Timer
        wdt_enable(WDTO_2S);
        //UART0_putchar('R');
            
        // Get one bytes for the length.
        rcv = UART1_getchar();
        p_length = (uint16_t)rcv;
            
        // Get the number of bytes specified
        char pass[p_length];
        for(int i = 0; i < p_length; ++i){
            pass[i] = UART1_getchar();
        }
        
        // Read in start address (4 bytes).
        wdt_reset();
        uint32_t start_addr = ((uint32_t)UART1_getchar()) << 24;
        start_addr |= ((uint32_t)UART1_getchar()) << 16;
        start_addr |= ((uint32_t)UART1_getchar()) << 8;
        start_addr |= ((uint32_t)UART1_getchar());
        
        // Read in size (4 bytes).
        wdt_reset();
        uint32_t size = ((uint32_t)UART1_getchar()) << 24;
        size |= ((uint32_t)UART1_getchar()) << 16;
        size |= ((uint32_t)UART1_getchar()) << 8;
        size |= ((uint32_t)UART1_getchar());
        
        // Get secret password inside bootloader.c
        uint8_t l = 0;
        uint8_t t[64] = {0};
        while(1){
            wdt_reset();
            t[l] = pgm_read_byte_far(&p[l]);
            if(t[l] != '\0')
            {
                l++;
            }
            else
                break;
        }
        
        // Compare secret password inside bootloader.c and password provided by readback tool
        // If they don't metch, output ERROR and stop executing rest code
        if(l == p_length){
            for(int j = 0; j < p_length; j++){
                if(pass[j] != t[j]){
                    UART1_putchar(ERROR);    // Acknowledge the frame.
                    while(1)
                    {
                        __asm__ __volatile__("");
                    }
                }
            }
        }
        else{
            UART1_putchar(ERROR);            // Acknowledge the frame.
            while(1)
            {
                __asm__ __volatile__("");
            }
        }  
        
        // Get AES key from EEPROM
        hextoraw(aes, key);
        
        // Pass Password checking, AES encrypt the requested data and send out to readback tool
        // Read the memory out to UART1.
        /*
         * The readback tool sent one frame at a time.
         * The bootloader will sent an acknowledge message to readback tool before sending each frame.
         * Each frame has 16 bytes AES encrypted data.
         * If requested data number is not a multiple of 16 bytes. Padding the last frame
         */
        for(int i = 0; i < ((size + 15) /16); ++i){
            
            // Get 16 Bytes data in AES encrypt data block tmp[16]
            int j = 0;
            if((i == size / 16) && (size % 16 != 0)) // If last frame is not a multiple of 16 bytes. Padding the last frame
            {
                for(uint32_t addr = start_addr + (i * 16); addr < start_addr + (i * 16) + (size % 16); ++addr)
                {
                    // Read a byte from flash.
                    tmp[j] = pgm_read_byte_far(addr);
                    wdt_reset();
                    j++;
                }
                for(; j < 16; ++j)
                {
                    tmp[j] = '0';
                }
                
            }
            else                                    // If data frame is a multiple of 16 bytes
            {
                for(uint32_t addr = start_addr + (i * 16); addr < start_addr + (i * 16) + 16; ++addr)
                {
                    // Read a byte from flash.
                    tmp[j] = pgm_read_byte_far(addr);
                    wdt_reset();
                    j++;
                }
            }
            
            // AES encrypt each frame
            AES128_ECB_encrypt(tmp, key, en);
            
            wdt_reset();
            UART1_putchar(OK);                     // Acknowledge the readback tool.
            
			// Write the encrypted data byte to UART1.			
            for(int k = 0; k < 16; ++k){ 
                wdt_reset();
                UART1_putchar(en[k]);
            }
        }
		
        while(1) __asm__ __volatile__(""); // Wait for watchdog timer to reset.
    }
    else      // If no jumper, boot firmware.
    {
        /*
         * Ensure the firmware is loaded correctly and boot it up.
         */
        // boot_firmware();
        UART1_putchar('B');
       
        // Start the Watchdog Timer.
        wdt_enable(WDTO_2S);
        // UART0_putchar('B');
        
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
        // Write out release message "Msg:" to UART0.
        for(int i = 0; i < 4; ++i)
            UART0_putchar(pgm_read_byte_far(&release_msg[i]));
        
        // Write out release message to UART0.
        wdt_reset();
        do
        {
            cur_byte = pgm_read_byte_far(addr + 1);
            UART0_putchar(cur_byte);
            ++addr;
        } while (cur_byte != 0);
        
        wdt_reset();
        // Write out current version of firmware "Ver:" to UART0.
        for(int i = 0; i < 6; ++i)
            UART0_putchar(pgm_read_byte_far(&current_version[i]));
        
        wdt_reset();
        // Write out current version of firmware to UART0 in hex_string format
        uint16_t a = eeprom_read_word(&fw_version);
        wdt_reset();
        printHexChar (a >> 8);
        printHexChar (a);
        
        // Stop the Watchdog Timer.
        wdt_reset();
        wdt_disable();
            
        /* Make the leap of faith. */
        asm ("jmp 0000");
    }
    
} // main

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
 * In hextoraw function, you need get the aes key from EEPROM
 * The EEPROM has 32 bytes Hex character
 * Convert 32 bytes Hex character to 16 Bytes AES Key
 */
void hextoraw(const uint8_t *aes, uint8_t * aeskey){
    // Get GCC Compiler AES key
    uint8_t tmp[32];
    for(int i = 0; i < 32; i+=2)
    {
        uint16_t tmp_key = 0;
        tmp_key = eeprom_read_word((uint16_t*)(aes + i));
        if(tmp_key == 0)
        {
            // Wait for watchdog timer to reset.
            while(1) __asm__ __volatile__("");
        }
        wdt_reset();
        tmp[i] = tmp_key;
        tmp[i+1] = tmp_key >> 8;
    }
    
    // Convert 32 bytes Hex character to 16 Bytes AES Key
    for(int i = 0; i < 32; i+=2)
    {
        uint8_t l = 0;
        if('a' <= tmp[i + 1] && tmp[i + 1] <= 'f'){
            l = (tmp[i + 1] - 'a' + 10) << 4;
        }
        else{
            l = (tmp[i + 1] - '0') << 4;
        }
        
        if('a' <= tmp[i] && tmp[i] <= 'f'){
            l += (tmp[i] - 'a' + 10);
        }
        else{
            l += (tmp[i] - '0');
        }
        
        aeskey[i/2] = l;
    }
}

// Print the uint8_t data in Hex Char format
void printHexChar(uint8_t input){
    char out;
    if((input / 16) < 10)
    {
        out = 48 + (input / 16);
    }
    else{
        out = 97 + (input / 16 - 10);
    }
    UART0_putchar(out);
    if((input % 16) < 10)
    {
        out = 48 + (input % 16);
    }
    else{
        out = 97 + (input % 16 - 10);
    }
    UART0_putchar(out);
}

