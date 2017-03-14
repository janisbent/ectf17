/*
 * UART driver code.
 */

#include <avr/io.h>
#include <avr/pgmspace.h>
#include <string.h>
#include <stdlib.h>
#include "uart.h"
#include "util.h"

/* init UART1
 * BAUD must be set and setbaud imported before calling this
 */
void BOOTLOADER_SECTION UART1_init(void)
{
    #include <util/setbaud.h>
    UBRR1H = UBRRH_VALUE; // Set the baud rate
    UBRR1L = UBRRL_VALUE;

    #if USE_2X
    UCSR1A |= (1 << U2X1);
    #else
    UCSR1A &= ~(1 << U2X1);
    #endif

    UCSR1B = (1 << RXEN1) | (1 << TXEN1); // Enable receive and transmit

    // Use 8-bit character sizes
    UCSR1C = (1 << UCSZ11) | (1 << UCSZ10);
}

void BOOTLOADER_SECTION UART1_putchar(uint8_t data)
{
    while(!(UCSR1A & (1 << UDRE1)))
    {
        // Wait for the last bit to send.
    }
    UDR1 = data;
}

bool UART1_data_available(void)
{
    return (UCSR1A & (1 << RXC1)) != 0;
}

/*
 * Fill a character array of specified size from uart.
 * will wait until enough data has been collected to fill entire array
 */
void BOOTLOADER_SECTION UART1_getsize(uint8_t* data, uint32_t size) {
  int i = 0;
  char cur_char;
  while (i < size)
  {
    cur_char = UART1_getchar();
    data[i] = cur_char;
    ++i;
  }
}

/*
 * Fill a character array of specified size from uart.
 * Assume that data points to a progmem location
 * will wait until enough data has been collected to fill entire array
 */
void BOOTLOADER_SECTION UART1_getsize_progmem(uint32_t addr, uint32_t size) {
    uint8_t page[SPM_PAGESIZE];
    uint32_t num_written = 0;
    while (num_written < size) {
        // Clear the page buffer
        memset(page, 0, SPM_PAGESIZE);

        // Read in up to a page of data
        for(uint32_t i = 0; i < MIN(SPM_PAGESIZE, size - num_written); ++i) {
            page[i] = UART1_getchar();
        }

        // Flash the page
        program_flash(addr + num_written, page);
        num_written += SPM_PAGESIZE;

        // Once we've read a page
        UART1_putchar(OK);
    }
}

uint8_t BOOTLOADER_SECTION UART1_getchar(void)
{
    while (!UART1_data_available())
    {
        /* Wait for data to be received */
    }
    /* Get and return received data from buffer */
    return UDR1;
}

void BOOTLOADER_SECTION UART1_flush(void)
{
    // Tell the compiler that this variable is not being used
    uint8_t __attribute__ ((unused)) dummy;  // GCC attributes
    while ( UART1_data_available() ) dummy = UDR1;
}

/* init UART0
 * BAUD must be set and setbaud imported before calling this
 */
void BOOTLOADER_SECTION UART0_init(void)
{
    #include <util/setbaud.h>
    UBRR0H = UBRRH_VALUE; // Set the baud rate
    UBRR0L = UBRRL_VALUE;

    #if USE_2X
    UCSR0A |= (1 << U2X0);
    #else
    UCSR0A &= ~(1 << U2X0);
    #endif

    UCSR0B = (1 << RXEN0) | (1 << TXEN0); // Enable receive and transmit

    // Use 8-bit character sizes
    UCSR0C = (1 << UCSZ01) | (1 << UCSZ00);
}

void BOOTLOADER_SECTION UART0_putchar(uint8_t data)
{
    while(!(UCSR0A & (1 << UDRE0)))
    {
        // Wait for the last bit to send
    }
    UDR0 = data;
}

bool UART0_data_available(void)
{
    return (UCSR0A & (1 << RXC0)) != 0;
}

uint8_t BOOTLOADER_SECTION UART0_getchar(void)
{
    while(!UART0_data_available())
    {
        /* Wait for data to be received */
    }
    /* Get and return received data from buffer */
    return UDR0;
}

void BOOTLOADER_SECTION UART0_flush(void)
{
    // Tell the compiler that this variable is not being used
    uint8_t __attribute__ ((unused)) dummy;  // GCC attributes
    while(UART0_data_available())
    {
        dummy = UDR0;
    }
}
