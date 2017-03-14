/*
 * bootloader.c
 * If Port B Pin 2 (PB2 on the protostack board) is pulled to ground the
 * bootloader will wait for data to appear on UART1 (which will be interpretted
 * as an updated firmware package).
 *
 * If the PB2 pin is NOT pulled to ground, but
 * Port B Pin 3 (PB3 on the protostack board) is pulled to ground, then the
 * bootloader will enter flash memory readback mode.
 */

#include <avr/io.h>
#include <avr/boot.h>
#include <avr/wdt.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <util/delay.h>

#include "uart.h"
#include "util.h"
#include "ecc.h"
#include "aes.h"
#include "sha2.h"
#include "hmac.h"

#define HMAC_KEY_SIZE 32
#define ECC_SIGN_SIZE sizeof(EccPoint)

#define MAX_FIRMWARE_SIZE 0x7800
#define MAX_RELMSG_SIZE 0x400

#define OK    ((uint8_t)0x00)
#define ERROR ((uint8_t)0x01)

#define BLOCK_RND(x) ((uint32_t)(ceil((float) x / AES_BLOCK_SIZE) * AES_BLOCK_SIZE))

// Don't worry about it
void configure_bootloader() __attribute__((section ("conf"))) __attribute__((aligned (SPM_PAGESIZE)));
extern uint32_t __start_conf;

// ** Main operations **
void BOOTLOADER_SECTION program_flash(uint32_t page_address, uint8_t *data);
void BOOTLOADER_SECTION load_firmware(void);
void BOOTLOADER_SECTION boot_firmware(void);
void BOOTLOADER_SECTION readback(void);
void BOOTLOADER_SECTION readback_getnonce(void);
void BOOTLOADER_SECTION write_firmware(uint32_t, uint16_t);

// ** EEPROM Data **
// Configuration data for the bootloader
typedef struct {
    uint8_t aes_key[AES_BLOCK_SIZE];
    uint8_t aes_iv[AES_BLOCK_SIZE];
    uint8_t hmac_key[HMAC_KEY_SIZE];
    EccPoint ecc_key;
    uint8_t is_configured;
    uint32_t rb_nonce;
} bl_config_t;
bl_config_t EEMEM saved_config;
bl_config_t config = {0};

// firmware info
uint16_t fw_size EEMEM = 0;
uint16_t fw_rmsg_size EEMEM = 0;
uint16_t fw_version EEMEM = 0;

// Temporary space in flash to store encrypted firmware
const uint8_t new_firmware[SPM_PAGESIZE + MAX_FIRMWARE_SIZE + MAX_RELMSG_SIZE] PROGMEM __attribute__((aligned (SPM_PAGESIZE)));

typedef enum {
    MSG_CONFIGURE = 1,
    MSG_UPDATE,
    MSG_READBACK_GETNONCE,
    MSG_READBACK,
    MSG_DONE
} __attribute__ ((packed)) msg_t;

void BOOTLOADER_SECTION die() {
    wdt_enable(WDTO_500MS);
    while (1) __asm__ __volatile__ ("");
}

int BOOTLOADER_SECTION main(void) {
    wdt_reset();
    wdt_disable();

    UART0_init();
    UART0_putchar('0');
    UART1_init();

    // Configure Port B Pins 2 and 3 as inputs.
    DDRB &= ~((1 << PB2) | (1 << PB3));

    // Enable pullups - give port time to settle.
    PORTB |= (1 << PB2) | (1 << PB3);

    // magic to load/init the config struct
    eeprom_read_block(&config, &saved_config, sizeof(bl_config_t));

    // Configure before doing anything else
    msg_t mtype = 0;
    if (!config.is_configured) {
        mtype = (msg_t) UART1_getchar();
        if (mtype == MSG_CONFIGURE) {
            UART1_putchar('C');

            // Run the configuration
            configure_bootloader();

            // Update config with correct values
            eeprom_read_block(&config, &saved_config, sizeof(bl_config_t));

            // We're all set, never let that happen again
            // GET NOP'd
            uint8_t page[SPM_PAGESIZE] = {0};
            page[SPM_PAGESIZE - 2] = '\x08';
            page[SPM_PAGESIZE - 1] = '\x95';
            program_flash(pgm_get_far_address(__start_conf), page);
        }
    } else {
        // If jumper is present on pin 2, start the message loop
        if (!(PINB & (1 << PB2))) {
            while (mtype != MSG_DONE) {
                // Read in message type from UART1 (1 byte)
                mtype = (msg_t) UART1_getchar();
                UART0_putchar(mtype);
                switch (mtype) {
                    case MSG_UPDATE:
                        UART1_putchar('U');
                        load_firmware();
                        die();
                        break;
                    case MSG_READBACK_GETNONCE:
                        UART1_putchar('N');
                        readback_getnonce();
                        break;
                    case MSG_READBACK:
                        UART1_putchar('R');
                        readback();
                        break;
                    case MSG_DONE: break;
                    default:
                        die();
                        break;
                }
            }
        }

        // Finally boot the firmware
        UART1_putchar('B');
        boot_firmware();
    }
} // main


void BOOTLOADER_SECTION sha256_progmem(uint32_t addr, uint32_t size, uint8_t* digest) {
    // Initialze the sha256 state
    SHA256_CTX ctx;
    sha256_Init(&ctx);

    // Arbitrary, just so we don't pull the whole thing into ram
    uint32_t hash_block = 256;
    uint8_t buf[hash_block];

    // Ingest all the data
    for (uint32_t end = addr + size; addr < end; addr += hash_block) {
        uint32_t len = MIN(hash_block, end - addr);
        memcpy_PF(buf, addr, len);
        sha256_Update(&ctx, buf, len);
    }

    // Finalize hash
    sha256_Final(&ctx, digest);
}


bool BOOTLOADER_SECTION hmac_verify_decrypt_offset_progmem(uint32_t sig_addr, uint32_t sig_len,
                                        uint32_t enc_addr, uint32_t enc_len,
                                        uint8_t *hmac, EccPoint *sig) {
    uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
    uint8_t data_hmac[SHA256_DIGEST_LENGTH] = {0};

    // Compute hash for verification
    sha256_progmem(sig_addr, sig_len, hash);
    wdt_reset();


    // Verify that the hmac matches
    for (uint32_t i = 0; i < 5; ++i) { // Just making sure
        hmac_sha256(config.hmac_key, HMAC_KEY_SIZE, hash, SHA256_DIGEST_LENGTH, data_hmac);
        if (memcmp(hmac, data_hmac, SHA256_DIGEST_LENGTH) != 0) {
            UART0_putchar('H');
            return false;
        }
        wdt_reset();
    }

    // Verify that the signature is correct. This may take a few seconds
    if (!ecdsa_verify(&config.ecc_key, hash, sig->x, sig->y)) {
        UART0_putchar('V');
        return false;
    }
    wdt_reset();

    // Needed for decrypting
    uint8_t page[SPM_PAGESIZE] = {0};                    // Temp page buffer
    uint8_t iv[AES_BLOCK_SIZE], next_iv[AES_BLOCK_SIZE]; // Keep track of IV's between pages
    memcpy(iv, config.aes_iv, AES_BLOCK_SIZE);           // Copy over first IV

    // Steps to decrypt from PROGMEM
    // 1. Pull down a page of encrypted data
    // 2. Decrypt it in place
    // 3. Flash it back to the temp buffer

    // All verified, decrypt the message
    for (uint32_t end = enc_addr + enc_len; enc_addr < end; enc_addr += SPM_PAGESIZE) {
        uint32_t len = MIN(SPM_PAGESIZE, end - enc_addr);

        // Copy in a page to decrypt
        memcpy_PF(page, enc_addr, len);


        // Save the last block as the next iv
        // This is unused when we reach the last page
        memcpy(next_iv, page + SPM_PAGESIZE - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

        // Decrypt the current block
        AES128_CBC_decrypt_buffer(page, len, config.aes_key, iv);

        // Flash it back
        program_flash(enc_addr, page);

        // Move to the next iv
        memcpy(iv, next_iv, AES_BLOCK_SIZE);
        wdt_reset();
    }

    return true;
}

bool BOOTLOADER_SECTION hmac_verify_decrypt(uint8_t *data, uint32_t len, uint8_t *hmac, EccPoint *sig) {
    uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
    uint8_t data_hmac[SHA256_DIGEST_LENGTH] = {0};

    // Compute hash for verification
    sha256_Raw(data, len, hash);
    wdt_reset();

    // Verify that the hmac matches
    for (uint32_t i = 0; i < 5; ++i) { // Just making sure
        hmac_sha256(config.hmac_key, HMAC_KEY_SIZE, hash, SHA256_DIGEST_LENGTH, data_hmac);
        if (memcmp(hmac, data_hmac, SHA256_DIGEST_LENGTH) != 0) {
            UART0_putchar('H');
            return false;
        }
        wdt_reset();
    }

    // Verify that the signature is correct. This may take a few seconds.
    if (!ecdsa_verify(&config.ecc_key, hash, sig->x, sig->y)) {
        UART0_putchar('C');
        return false;
    }
    wdt_reset();

    // All verified, decrypt the message
    AES128_CBC_decrypt_buffer(data, len, config.aes_key, config.aes_iv);
    wdt_reset();

    return true;
}

/*
 *  Read in secret keys and store config struct into eprom
 */
void configure_bootloader() {
    // Read in aes key
    UART1_getsize(config.aes_key, AES_BLOCK_SIZE);

    // Read in aes iv (16 bytes).
    UART1_getsize(config.aes_iv, AES_BLOCK_SIZE);

    // Read in HMAC key
    UART1_getsize(config.hmac_key, HMAC_KEY_SIZE);

    // Read in ECC public key
    UART1_getsize((uint8_t *) &config.ecc_key, ECC_SIGN_SIZE);

    // Set initial nonce
    config.rb_nonce = 0;

    // We're done, don't do this again
    config.is_configured = true;

    // Write config struct to eeprom
    eeprom_write_block(&config, &saved_config, sizeof(bl_config_t));
}


void BOOTLOADER_SECTION readback_getnonce() {
    // Send the nonce back (big endian)
    for (int i = 0; i < 4; i++) {
        UART1_putchar(((config.rb_nonce) >> (8 * i)) & 0xff);
    }
}

/*
 * Interface with host readback tool.
 */
void BOOTLOADER_SECTION readback(void) {
    uint8_t hmac[SHA256_DIGEST_LENGTH] = {0};
    uint8_t data[AES_BLOCK_SIZE] = {0};
    EccPoint sig = {0};

    wdt_disable();

    // Read in sig and AES block
    UART1_getsize((uint8_t *) &sig, ECC_SIGN_SIZE);
    UART1_getsize(hmac, SHA256_DIGEST_LENGTH);
    UART1_getsize(data, AES_BLOCK_SIZE);
    wdt_reset();

    // Verify and decrypt the message
    if (!hmac_verify_decrypt(data, AES_BLOCK_SIZE, hmac, &sig)) {
        UART0_putchar('E');
        die();
    }
    wdt_reset();

    // Pull out the values from the message
    uint32_t nonce = STR2INT(data);
    uint32_t start_addr = STR2INT(data + 4);
    uint32_t size = STR2INT(data + 8);
    uint32_t end_addr = start_addr + size;

    // This prevents replays
    if (nonce != config.rb_nonce + 1) {
        UART0_putchar('N');
        die();
    }

    // Update the nonce
    config.rb_nonce = nonce;
    eeprom_write_block(&config, &saved_config, sizeof(bl_config_t));

    // We *may* be sending back a huge block of memory,
    // so we'll encrypt and send one block at a time
    uint8_t enc_block[AES_BLOCK_SIZE];  // Buffer to hold the encrypted memory
    uint8_t last_block[AES_BLOCK_SIZE]; // IV for the next block
    uint8_t mem_buf[AES_BLOCK_SIZE];    // Holds memory pulled in from flash

    // The initial last_block is the actual iv
    memcpy(last_block, config.aes_iv, AES_BLOCK_SIZE);

    // Encrypt and send block by block
    for (uint32_t addr = start_addr; addr < end_addr; addr += AES_BLOCK_SIZE) {
        // Pull in a block of memory from flash
        memcpy_PF(mem_buf, addr, AES_BLOCK_SIZE);

        // Encrypt it
        AES128_CBC_encrypt_buffer(enc_block, mem_buf,
                                  MIN(AES_BLOCK_SIZE, end_addr - addr),
                                  config.aes_key, last_block);

        // Keep track of the last block as the IV
        memcpy(last_block, enc_block, AES_BLOCK_SIZE);

        // Print the block out to UART1
        for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
            UART1_putchar(enc_block[i]);
        }
        wdt_reset();
    }
}

/*
 *  Read in firmware
 */
void BOOTLOADER_SECTION load_firmware(void) {
    uint32_t new_firmware_addr = pgm_get_far_address(new_firmware);
    uint32_t firmware_size = 0, enc_bundle_size = 0, rmsg_size = 0;
    uint16_t version = 0;

    // HMAC buffers
    uint8_t pre_msg_hmac[SHA256_DIGEST_LENGTH] = {0};
    uint8_t total_msg_hmac[SHA256_DIGEST_LENGTH] = {0};

    // Signatures
    EccPoint pre_msg_sig = {0};
    EccPoint total_msg_sig = {0};

    // Initial info about firmware
    uint8_t pre_msg[AES_BLOCK_SIZE] = {0};

    // Start the Watchdog Timer
    wdt_enable(WDTO_4S);

    /*
     * Pre-message
     * Contains information about the incoming firmware bundle
     * 16 bytes
     * +--------------------------------+---------+---------+-------------+
     * | Size of enc(firmware + relmsg) | Version | FW Size | RelMsg Size |
     * +--------------------------------+---------+---------+-------------+
     *
     * This message is signed, the verification info is received as follows
     * +---------+------+------------------+
     * | ECC sig | HMAC | enc(Pre-message) |
     * +---------+------+------------------+
     */

    // Fetch Pre-message and verification info
    UART1_getsize((uint8_t *) &pre_msg_sig, ECC_SIGN_SIZE); // Signature
    UART1_getsize(pre_msg_hmac, SHA256_DIGEST_LENGTH);      // HMAC
    UART1_getsize(pre_msg, AES_BLOCK_SIZE);                 // ctxt
    wdt_reset();

    // Copy the verification info into the first page of the flash buffer *order matters*
    uint8_t page[SPM_PAGESIZE] = {0};
    memcpy(page, (uint8_t *) &pre_msg_sig, ECC_SIGN_SIZE);                        // Signature
    memcpy(page + ECC_SIGN_SIZE, pre_msg_hmac, SHA256_DIGEST_LENGTH);             // HMAC
    memcpy(page + ECC_SIGN_SIZE + SHA256_DIGEST_LENGTH, pre_msg, AES_BLOCK_SIZE); // Pre-message
    program_flash(new_firmware_addr, page);

    wdt_reset();

    // Verify and decrypt pre-message
    if (!hmac_verify_decrypt(pre_msg, AES_BLOCK_SIZE, pre_msg_hmac, &pre_msg_sig)) {
        UART0_putchar('P');
        die();
    }
    wdt_reset();

    // Parse out size and version (Big endian, to little endian)
    enc_bundle_size = STR2INT(pre_msg);
    version = STR2INT(pre_msg + 4);
    firmware_size = STR2INT(pre_msg + 8);
    rmsg_size = STR2INT(pre_msg + 12);

    // Compare to old version and abort if older (note special case for version 0).
    if (version != 0 && version <= eeprom_read_word(&fw_version)) {
        die();
    }

    // Once we've gotten to this point, send an OK
    UART1_putchar(OK);

    /*
     * Bundle
     * Given the info from the pre-message, start reading in the encrypted bundle
     * The bundle itself is the following
     * +----------+--------+
     * | Firmware | RelMsg |
     * +----------+--------+
     *
     * The verification info for this combines the bundle with the pre-message info
     * A signature is created for the following
     * +------------------------------------+------------------------------+-------------+
     * | Full Pre-message verification info | '\0' padding to SPM_PAGESIZE | enc(Bundle) |
     * +------------------------------------+------------------------------+-------------+
     *
     * This new verification info is also received as
     * +---------+------+
     * | ECC sig | HMAC |
     * +---------+------+
     */

    UART0_putchar(OK);

    // Read verification info for the total bundle
    UART1_getsize((uint8_t *) &total_msg_sig, ECC_SIGN_SIZE);
    UART1_getsize(total_msg_hmac, SHA256_DIGEST_LENGTH);
    UART1_putchar(OK);
    wdt_reset();

    UART0_putchar(OK);

    // Once we've programmed the first pre-msg
    UART0_putchar(OK);
    // Read enc firmware blob of specified size, rounded up to the nearest block
    wdt_disable();
    UART1_getsize_progmem(new_firmware_addr + SPM_PAGESIZE, BLOCK_RND(enc_bundle_size));
    // Once we've read all the firmware
    UART0_putchar(OK);
    wdt_reset();

    // Verify everything and decrypt the firmware
    if (!hmac_verify_decrypt_offset_progmem(
            new_firmware_addr, SPM_PAGESIZE + enc_bundle_size, // Hash the first page with the bundle
            new_firmware_addr + SPM_PAGESIZE, enc_bundle_size, // Decrypt only the bundle
            total_msg_hmac, &total_msg_sig)) {
        UART0_putchar('E');
        die();
    }
    // Once we've verified and decrypted
    UART0_putchar(OK);
    wdt_reset();

    // Flash the decrypted firmware
    write_firmware(new_firmware_addr + SPM_PAGESIZE, firmware_size);
    wdt_reset();

    // Update version number and firmware size in EEPROM.
    // Don't change the version number for the debug firmwware
    if (version != 0) eeprom_update_word(&fw_version, version);
    eeprom_update_word(&fw_size, firmware_size);
    eeprom_update_word(&fw_rmsg_size, rmsg_size);
    wdt_reset();

    UART0_putchar('D');
    UART1_putchar(OK);
}

/*
 * Actually flash the dern thing
 */
void BOOTLOADER_SECTION write_firmware(uint32_t new_firmware, uint16_t new_firmware_size) {
    uint8_t buf[SPM_PAGESIZE] = {0};
    for (uint16_t i = 0; i < new_firmware_size; i += SPM_PAGESIZE) {
        memset(buf, 0, SPM_PAGESIZE);
        memcpy_PF(buf, new_firmware + i, SPM_PAGESIZE);
        program_flash(i, buf);
    }
}


/*
 * Ensure the firmware is loaded correctly and boot it up.
 */
void BOOTLOADER_SECTION boot_firmware(void) {
    // Start the Watchdog Timer.
    wdt_enable(WDTO_2S);

    uint8_t cur_byte;
    uint32_t addr = (uint32_t)eeprom_read_word(&fw_size);

    // Reset if firmware size is 0 (indicates no firmware is loaded).
    if (addr == 0) {
        // Wait for watchdog timer to reset.
        die();
    }

    wdt_reset();

    // Write out release message to UART0.
    do {
        cur_byte = pgm_read_byte_far(addr++);
        UART0_putchar(cur_byte);
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
void BOOTLOADER_SECTION program_flash(uint32_t page_address, uint8_t *data) {
    int i = 0;

    boot_page_erase_safe(page_address);

    for (i = 0; i < SPM_PAGESIZE; i += 2) {
        uint16_t w = data[i];    // Make a word out of two bytes
        w += data[i + 1] << 8;
        boot_page_fill_safe(page_address + i, w);
    }

    boot_page_write_safe(page_address);
    boot_rww_enable_safe(); // We can just enable it after every program too
}
