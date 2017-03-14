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
 *
 * Firmware Update Steps:
 * 1. Provisioner sends encrypted frames consisting of a constant, firmware version
 * no, number of blocks to be sent fw size, and new secure random. (All messages are
 * sent with hash and verified for integrity protection.)
 * 2. Bootloader decrypts and verifies constant and checks the validity of the version
 * number. If valid, it sends an ok message to the provisioner.
 * 3. The provisioner now sends the bootloader the firmware encrypted one frame at a
 * time (128 bytes). For each block, the bootloader decrypts the data, verifies the
 * integrity and saves to a temporary location on the flash.
 * 4. After the entire firmware has been received, the bootloader copies the firware
 * to location 0 and sends a success message to the provisioner.
 *
 * Frames are stored in an intermediate buffer until a complete page has been
 * sent, at which point the page is written to flash. See program_flash() for
 * information on the process of programming the flash memory. Note that if no
 * frame is received after 2 seconds, the bootloader will time out and reset.
 *
 *
 * Readback Steps:
 * 1. Provisioner sends the requested start address and size to the bootloader.
 * 2. The bootloader responds back with a random challenge which the provisioner
 * has to solve with the shared key in order to authenticate.
 * 3. The provisioner receieves the random, hashes it along with the secret key
 * and sends the first 16 bytes of hash to the bootloader.
 * 4. The bootloader computes the hash using the sent random and its key and mmatches
 * it with the hash that was sent. If the 2 match, the user is authenticated.
 * 5. The bootloader now reads the requested flash area one block at a time (128 bytes),
 * encrypts it and sends to the provisioner who decrypts it for reading.
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
#include "sha1.h"
#include "crypto.h"
#include "uart.h"
#include "message.h"
#include "config.h"
#include "readback.h"
#include "firmware.h"

/* Status Codes: Used for messages sent over UART */
#define OK    ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)

/* Temporary Space */
#define TEMP_PAGE 40960  // Address to flash temporary firmware
// The device uses the non-active boot address for caching of a firmware and 
// once the entirety of the firmware has been verified, then the cache would
// be copied over to page 0

/* Function Prototypes */
void random_delay(uint16_t);
void reset_board(void);

void load_firmware(void);
void readback(void);
void boot_firmware(void);
bool program_flash(uint32_t, uint8_t*);

/* Global Variables */
crypt_keys_t keys;
UART_msg_t umsg;

/* EEPROM storage variables */
uint16_t fw_version EEMEM = 0;
uint16_t fw_size EEMEM = 0;

int main(void) {
    // Init UART0 and UART1 (virtual com port)
	UART0_init();
    UART1_init();
    wdt_reset();

    // Init the configuration parameters
	random_delay(2400);  // Add a small delay to offset timing based attacks
	random_delay(2400);
    config_init(&keys);
    wdt_reset();

    // Configure Port B Pins 2 and 3 as inputs.
    DDRB &= ~((1 << PB2) | (1 << PB3));

    // Enable pullups - give port time to settle.
    PORTB |= (1 << PB2) | (1 << PB3);

    // If jumper is present on pin 2, load new firmware.
    if(!(PINB & (1 << PB2))) {
		// Update the firmware
		UART1_putchar('U');
		load_firmware();
    } else if(!(PINB & (1 << PB3))) {
		// Initialize readback mode
		UART1_putchar('R');
		readback();
    } else {
    	// Attempt to boot the firmware
        UART1_putchar('B');
        boot_firmware();
    }
} // main

/*
 * Add some random delay in the code (max delay specified by parameter)
 */
void random_delay(uint16_t max_delay) {
    // Use keys.rand to generate a random amount of delay
	uint32_t delay1 = extract_uint32_t(keys.rand, 0) % (max_delay / 2);
	uint32_t delay2 = extract_uint32_t(keys.rand, 4) % (max_delay / 2);

	for (uint16_t i = 0; i < delay1; i++)
		_delay_ms(1);
	wdt_reset();
	for (uint16_t i = 0; i < delay2; i++)
		_delay_ms(1);
	wdt_reset();
}

/*
 * Wait for the watchdog timer to reset.
 */
void reset_board(void) {
	while(1)
		__asm__ __volatile__("");
}

/*
 * Interface with host readback tool.
 */
void readback(void) {
    // Array to hold the hash set to the size of the key
	uint8_t self_hash[SHA1_HASH_BYTES];
	// Holds whether or not the firmware is authorized
	bool auth_result;

    // Start the Watchdog Timer with a 2 second timeout
    wdt_enable(WDTO_2S);

    // Read first frame containing the start address and the size (4 bytes each for a total of 8 bytes)
    recv_message(&umsg, 8);
    // Use helper functions to load them into variables
    uint32_t addr = rdb_load_addr(&umsg);
    uint32_t size = rdb_load_size(&umsg);
    wdt_reset();

    // Create a random number from the previous seed and send to the receiver
    rdb_send_auth_random(&keys, &umsg);
    wdt_reset();

    // Read second frame containing the authentication hash
    recv_message(&umsg, KEY_SIZE);
    random_delay(1000);  // Timing attack offset
    // Verify the hash we just got above
    auth_result = rdb_verify_auth_hash(&umsg, self_hash, &keys);
    wdt_reset();
    random_delay(1000); // Timing attack offset
    // If successful, encrypt the flash data and send to the receiver. If unsuccessful, send
    // error and time out.
    if (auth_result == 1) {
        // If verified, send an OK message
        UART1_putchar(OK);

    	// Setup the keys to be used for encryption
		crypt_init(self_hash, &keys);

		// Iterate through the address space and read blocks of data
		for(uint32_t a = addr; a < (addr + size); a += MAX_LEN) {
			uint8_t tmp_data[MAX_LEN];

			for (uint8_t i = 0; i < MAX_LEN; i++) {
				// Read byte from flash and add, if size exceeded add padding for crypto operations
				if ((a+i) < (addr+size)) {
					tmp_data[i] = (uint8_t) pgm_read_byte_far(a+i);
				} else {
					tmp_data[i] = PAD_CHAR;  // PAD_CHAR is #defined
				}
				wdt_reset();
			}

			// Encrypt the data and send to uart interface
			rdb_send_enc_data(tmp_data, &umsg, &keys, MAX_LEN);

			// Break out of the loop if an OK is not received
			char ack = UART1_getchar();
			if (ack != OK)
				break;
		}
    } else {
        // Send an error message
    	UART1_putchar(ERROR);
    }

    // Reset the board
    reset_board();
}

/*
 * Load the firmware into flash.
 */
void load_firmware(void) {
    // Variables to hold all of the information about the firmware
	uint8_t tmp_hash[KEY_SIZE];
	uint8_t tmp_enc[MAX_LEN];
	uint8_t tmp_data[MAX_LEN];
	uint8_t page_data[MAX_LEN*2];
	uint16_t proc_frames = 0;
	uint32_t page_address = 0;

    // Start the Watchdog Timer
    wdt_enable(WDTO_2S);

    // Read the first frame containing the hash and the numbers (constant, no, size and secure random)
    recv_message(&umsg, KEY_SIZE + 32);
    // The first KEY_SIZE bytes are the hash
    copy_block(umsg.msg, tmp_hash, 0, 0, KEY_SIZE);
    // The rest of it is the encrypted frame
    copy_block(umsg.msg, tmp_enc, KEY_SIZE, 0, 32);
    wdt_reset();

    // Decrypt the first frame and save the information if valid (i.e. hash and constant match)
    crypt_init(tmp_hash, &keys);
    // Check the integrity of the data and size of firmware
    bool integrity = fw_decrypt_and_integrity(tmp_enc, tmp_data, tmp_hash, &keys, 32);
    uint32_t constant = fw_load_constant(tmp_data);
    uint16_t num_frames = (uint16_t) fw_load_num_frames(tmp_data);
    wdt_reset();

    if (integrity == 1 && constant == DEC_CONST && num_frames < 250) {
    	// Extract the version no, size and the new seed
		uint32_t version_no = fw_load_version(tmp_data);
		uint32_t size = fw_load_fw_size(tmp_data);
		copy_block(tmp_data, keys.rand, 16, 0, KEY_SIZE);
		wdt_reset();

		// Ensure that version number is newer that the current or zero
		random_delay(1000);  // Timing attack offset
		random_delay(1000);  // Timing attack offset
		if (version_no == 0 || version_no >= eeprom_read_word(&fw_version)) {
			UART1_putchar(OK); // Acknowledge the metadata

			// Start reading the data from the receiver and writing to flash memory
			uint8_t status = 1;
			while (proc_frames < num_frames) {
				// Get the hash and encrypted message, and decrypt the message
				recv_message(&umsg, MAX_LEN + KEY_SIZE);
				copy_block(umsg.msg, tmp_hash, 0, 0, KEY_SIZE);
				copy_block(umsg.msg, tmp_enc, KEY_SIZE, 0, MAX_LEN);
				integrity = fw_decrypt_and_integrity(tmp_enc, tmp_data, tmp_hash, &keys, MAX_LEN);
				wdt_reset();

				if (integrity == 1) {
					// If this is the second frame for this page, program the flash. Otherwise, just
					// save in the temp buffer. We do this because the flash has to be programmed in
					// blocks of 256 but the frames are 128 bytes each. 
					if (proc_frames % 2 == 1) {
						copy_block(tmp_data, page_data, 0, MAX_LEN, MAX_LEN);

						// Program the flash (data should already be padded with 0xFF). Keep trying till
						// the page matches the data.
						while(program_flash(page_address + TEMP_PAGE, page_data) == 0);
						page_address += (MAX_LEN * 2);
					} else {
						copy_block(tmp_data, page_data, 0, 0, MAX_LEN);
					}

					proc_frames++;
					wdt_reset();

					UART1_putchar(OK); // Acknowledge the frame.
				} else {
					UART1_putchar(ERROR);

					// The status must be zero and the board should be reset
					status = 0;
					reset_board();
				}
				wdt_reset();
			}

			random_delay(1000);  // Timing attack offset
			random_delay(1000);  // Timing attack offset
			if (status == 1) {
				// Update the seed in EEPROM
				config_update_seed(&keys);
				wdt_reset();

				// Update version number and size in EEPROM as the flash has been successful
				// Note, update version only if it's non zero to prevent a downgrade attack
				if (version_no != 0) {
					eeprom_update_word(&fw_version, version_no);
					wdt_reset();
				}
				eeprom_update_word(&fw_size, size);
				wdt_reset();

				// Copy over all the bytes from the temp location to location 0. Location 0
				// is used by the program to load the firmware
				page_address = 0;
				for (uint32_t i = 0; i < (num_frames * MAX_LEN); i += (MAX_LEN * 2)) {
					for (uint16_t j = 0; j < (MAX_LEN * 2); j++) {
						page_data[j] = (uint8_t) pgm_read_byte_far(i + j + TEMP_PAGE);
						wdt_reset();
					}
					// Keep trying till the page matches the data.
					while (program_flash(page_address, page_data) == 0);
					page_address += (MAX_LEN * 2);

					wdt_reset();
				}

				UART1_putchar(OK); // Acknowledge that update has completed
			}
		} else {
			UART1_putchar(ERROR);
		}
    } else {
    	UART1_putchar(ERROR);
    }

    // Reset the board
    reset_board();
}

/*
 * Ensure the firmware is loaded correctly and boot it up.
 */
void boot_firmware(void) {
    // Start the Watchdog Timer.
    wdt_enable(WDTO_2S);

    // Write out the release message.
    uint8_t cur_byte;
    uint16_t addr = eeprom_read_word(&fw_size);

    // Reset if firmware size is 0 (indicates no firmware is loaded).
    if(addr == 0) {
        reset_board();
    }
    wdt_reset();

    // Write out release message to UART0.
    do {
		cur_byte = pgm_read_byte_far(addr);
		UART0_putchar(cur_byte);
		addr++;
	} while (cur_byte != 0);

    // Stop the Watchdog Timer.
    wdt_reset();
    wdt_disable();

    /* Make the leap of faith */
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
bool program_flash(uint32_t page_address, uint8_t *data) {
    boot_page_erase_safe(page_address);

    for(uint16_t i = 0; i < MAX_LEN * 2; i += 2) {
        uint16_t w = data[i];    // Make a word out of two bytes
        w += data[i+1] << 8;
        boot_page_fill_safe(page_address+i, w);
    }

    boot_page_write_safe(page_address);
    boot_rww_enable_safe(); // We can just enable it after every program too

    // Read the entire page back from the flash and verify that the data matches.
	// If the data does not match, we should return a 0 to the caller indicating
	// that the flash failed.
	for (uint16_t i = 0; i < MAX_LEN * 2; i++) {
		uint8_t d = (uint8_t) pgm_read_byte_far(page_address+i);
		wdt_reset();

		if (data[i] != d)
			return false;
	}
	return true;
}
