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
 */

#include <avr/io.h>
#include <stdint.h>
#include <stdio.h>
#include <util/delay.h>
#include "uart.h"
#include <avr/boot.h>
#include <avr/wdt.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>

#include "norx/norx.h"

// 120 packets = 30K firmware
#define PKT_COUNT 120
#define MSG_SIZE 1024

#define FIRMWARE_SIZE (PKT_COUNT * SPM_PAGESIZE)

#define NCE_SIZE (2 * (NORX_W / 8))
#define KEY_SIZE (4 * (NORX_W / 8))
#define TAG_SIZE (4 * (NORX_W / 8))

#define HDR_SIZE (sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + MSG_SIZE)
#define PKT_SIZE (NCE_SIZE + SPM_PAGESIZE + TAG_SIZE)

// Allocate an entire page for simplicity
static const uint8_t
release_version[SPM_PAGESIZE] __attribute__ ((section (".rel_ver"))) = {0};

static const uint8_t
release_message[MSG_SIZE] __attribute__ ((section (".rel_msg"))) = {0};

static const uint8_t
secret_key_encrypt[KEY_SIZE] __attribute__ ((section (".skey1"))) = SKEY1;

static const uint8_t
secret_key_decrypt[KEY_SIZE] __attribute__ ((section (".skey2"))) = SKEY2;

static uint8_t secret_key_ram[KEY_SIZE];
static uint8_t header_buf[HDR_SIZE];
static uint8_t packet_buf[PKT_SIZE];
static uint8_t ptext_buf[SPM_PAGESIZE];

/* We embed information used during runtime (such as pkt_no and is_err) in
 * header_buf so that if this information is incorrect or has been manipulated
 * during runtime, the data in packet_buf cannot be decrypted.
 */
static uint8_t  *const pkt_no = header_buf + 0;
static uint8_t  *const is_err = header_buf + 1;
static uint16_t *const hdr_version = (uint16_t *)(header_buf + 2);
static uint8_t  *const hdr_message = (uint8_t  *)(header_buf + 4);

static uint8_t *const nonce = packet_buf;
static uint8_t *const ctext = packet_buf + NCE_SIZE;


void write_page(uint16_t page, uint8_t *data);
void load_firmware(void);
void boot_firmware(void);
void readback(void);
void print_buffers_debug(void);
static inline void wipe_buffers(void);

static inline void erase_firmware(void) {
    wipe_buffers();

    // Erase release message, buffer is zeroes
    for (uint16_t i = 0; i < MSG_SIZE; i += SPM_PAGESIZE) {
        wdt_reset();
        write_page((uint16_t)(release_message + i), hdr_message + i);
    }

    // Erase FW
    for (uint16_t i = 0; i < FIRMWARE_SIZE; i += SPM_PAGESIZE) {
        wdt_reset();
        boot_page_erase_safe(i);
    }

    // Keep release version so that it can't be reverted
    // boot_page_erase_safe(release_version);
}

static inline void wipe_buffers(void) {
    for (uint16_t i = 0; i < KEY_SIZE; ++i)
        secret_key_ram[i] = 0;

    for (uint16_t i = 0; i < SPM_PAGESIZE; ++i)
        ptext_buf[i] = 0;

    for (uint16_t i = 0; i < HDR_SIZE; ++i)
        header_buf[i] = 0;

    for (uint16_t i = 0; i < PKT_SIZE; ++i)
        packet_buf[i] = 0;
}

static void do_reset(void) {
    wdt_enable(WDTO_120MS);
    wipe_buffers();
    while(1) __asm__ __volatile__("");
}


uint8_t ADC_getchar() {
    // Toggle between 1.1v and 2.56v clock to mess up the next conversion 
    // (The datasheet explicitly tells us not to do this)
    // ADMUX  ^= _BV(REFS1);

    // Set ADSC to 1 to begin conversion
    ADCSRA |= _BV(ADSC);

    // ADSC is set to 0 once conversion ends
    while (ADCSRA & _BV(ADSC))
        ;

    // Output of conversion
    uint8_t low_byte  = ADCL;
    uint8_t high_byte = ADCH;

    // xor them --- the only entropy we really have 
    // are the lower-order bytes, but this can't hurt
    return low_byte ^ high_byte;
}

static inline uint8_t cyclic_shift(uint8_t x, uint8_t i) {
    return (x << i) | (x >> (8 - i));
}

uint8_t random_byte() {
        // Distribute entropy in LSB across all bits
        return   cyclic_shift(ADC_getchar(), 0)
               ^ cyclic_shift(ADC_getchar(), 1)
               ^ cyclic_shift(ADC_getchar(), 2)
               ^ cyclic_shift(ADC_getchar(), 3)
               ^ cyclic_shift(ADC_getchar(), 4)
               ^ cyclic_shift(ADC_getchar(), 5)
               ^ cyclic_shift(ADC_getchar(), 6)
               ^ cyclic_shift(ADC_getchar(), 7);
}


void ADC_init(void) {
    // Used to generate random numbers

    // Differential input on ADC0, 200x gain
    ADMUX  |= _BV(MUX3) | _BV(MUX1);

    // Internal 1.1v (Technically not supposed to be used with above setting,
    // but increases variance of RNG)
    ADMUX  |= _BV(REFS1);

    // Internal 2.56v (This is the reccomended setting)
    // ADMUX  |= _BV(REFS1) | _BV(REFS0);

    // Set prescaler to 128
    ADCSRA |= _BV(ADPS2) |_BV(ADPS1) |_BV(ADPS0);

    // enable the ADC
    ADCSRA |= _BV(ADEN);
}


int main(void) {
    // TODO call again incase skipped
    cli();

    wipe_buffers();

    // Init UART1 (virtual com port)
    UART1_init();
    UART0_init();

    // Configure Port B Pins 2 and 3 as inputs.
    DDRB &= ~((1 << PB2) | (1 << PB3));

    // Enable pullups - give port time to settle.
    PORTB |= (1 << PB2) | (1 << PB3);

    // Set up RNG
    ADC_init();

    _delay_ms(1000);

    // If jumper is present on pin 2, load new firmware.
    if (!(PINB & (1 << PB2))) {
        UART1_putchar('U');
        load_firmware();
    } else if (!(PINB & (1 << PB3))) {
        UART1_putchar('R');
        readback();
    } else {
        UART1_putchar('B');
        boot_firmware();
    }
}

/*
 * Interface with host readback tool.
 */
void readback(void) {
    wdt_reset();
    wipe_buffers();
    wdt_enable(WDTO_60MS);

    *hdr_version = pgm_read_word_near(release_version);

    // Load our secret key into RAM for encrypting
    for (uint8_t i = 0; i < KEY_SIZE; i++)
        secret_key_ram[i] = pgm_read_byte_far(secret_key_encrypt + i);

    for (*pkt_no = 0; *pkt_no < PKT_COUNT; ++*pkt_no) {
        wdt_reset();

        // Set up a transmission using our buffers
        for (uint8_t i = 0; i < NCE_SIZE; i++)
            nonce[i] = random_byte();

        for (uint16_t i = 0; i < SPM_PAGESIZE; ++i)
            ptext_buf[i] = pgm_read_byte_near(*pkt_no * SPM_PAGESIZE + i);

        size_t dummy;
        norx_aead_encrypt(
            ctext,      &dummy,
            header_buf, 4,
            ptext_buf,  SPM_PAGESIZE,
            NULL,       0,
            nonce, secret_key_ram);

        // Send unique header for each packet
        for (uint16_t i = 0; i < 4; i++)
            UART1_putchar(header_buf[i]);

        // TODO swap packet_buf addr and ptext so we don't read from ctext?
        for (uint16_t i = 0; i < PKT_SIZE; i++)
            UART1_putchar(packet_buf[i]);
    }

    wipe_buffers();
    do_reset();
}


void load_firmware(void) {
    wdt_reset();
    wipe_buffers();
    wdt_enable(WDTO_500MS);
    // Load firmware version and secret key into header
    for (uint16_t i = 2; i < HDR_SIZE; ++i)
        header_buf[i] = UART1_getchar();        /* SKIP FIRST LOOP FOR VERSION */

    // Load version on chip
    uint16_t cur_version = pgm_read_word_near(release_version);

    // Error if new firmware version is non-zero and less than current
    *is_err |= (*hdr_version != 0) && (*hdr_version < cur_version);

    if (*is_err)
        do_reset();

    // Load our secret key into RAM for decrypting
    for (uint8_t i = 0; i < KEY_SIZE; ++i)
        secret_key_ram[i] = pgm_read_byte_far(secret_key_decrypt + i);

    // Start recieve packets
    for (*pkt_no = 0; *pkt_no < PKT_COUNT; ++*pkt_no) {
        wdt_reset();

        // Read in packet_buf
        for (uint16_t i = 0; i < PKT_SIZE; ++i)
            packet_buf[i] = UART1_getchar();

        // Decrypt packet_buf into ptext_buf using header_buf
        // Make is_err non-zero if there was an error in the past or now
        size_t dummy;
        *is_err |= norx_aead_decrypt(
                        ptext_buf,             &dummy,
                        header_buf,            HDR_SIZE,
                        ctext,                 SPM_PAGESIZE + TAG_SIZE,
                        NULL,                  0,
                        nonce, secret_key_ram);

        if (*is_err) {
            wdt_reset();
            erase_firmware();
            wipe_buffers();
            do_reset();
        }

        // Write decrypted page
        write_page(*pkt_no * SPM_PAGESIZE, ptext_buf);
    }

    wdt_reset();

    // Key is no longer needed, destroy it
    for (uint8_t i = 0; i < KEY_SIZE; ++i)
        secret_key_ram[i] = 0;

    // Write release message
    for (uint16_t i = 0; i < MSG_SIZE; i += SPM_PAGESIZE)
        write_page((uint16_t)(release_message + i), hdr_message + i);

    // Update version number unless it's a debug version
    if (*hdr_version != 0) {
       /* Note that because we're writing a page we'll be overflowing 254 bytes
        * into hdr_message but this doesn't matter since we don't care what's
        * in anything but the first 2 bytes. (The 254 bytes should be zeroed, 
        * anyway.)
        */
        write_page((uint16_t)release_version, (uint8_t *)hdr_version);
    }

    // Enable RWW section only if we successfully wrote firmware
    boot_rww_enable_safe();

    wipe_buffers();
    do_reset();
}


/*
 * Ensure the firmware is loaded correctly and boot it up.
 */
void boot_firmware(void) {
    wdt_reset();
    wipe_buffers();

    if (!pgm_read_byte_near(release_message))
        do_reset();

    uint16_t version = pgm_read_word_near(release_version);
    UART0_putchar((char)version);
    UART0_putchar((char)(version >> 8));
    
    // Write out the release message for non-null characters
    for (uint16_t i = 0; i < MSG_SIZE; i++) {
        uint8_t ch = pgm_read_byte_near(release_message + i);
        if (ch) UART0_putchar(ch);
    }

    // Make the leap of faith.
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
void write_page(uint16_t page, uint8_t *data) {
    boot_page_erase_safe(page);

    for (uint16_t i = 0; i < SPM_PAGESIZE; i += 2) {
        // Make a word out of two bytes, destroying previous data as an added
        // security measure
        uint16_t w;

        w = data[i];
        data[i] = 0;

        w |= data[i+1] << 8;
        data[i+1] = 0;

        boot_page_fill_safe(page + i, w);
    }

    boot_page_write_safe(page);
}
