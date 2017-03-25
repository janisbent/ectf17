/*
 * UART driver code.
 */

#include <avr/io.h>
#include "uart.h"

/* init UART1
 * BAUD must be set and setbaud imported before calling this
 */
void UART1_init(void)
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

void UART1_putchar(unsigned char data)
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

unsigned char UART1_getchar(void)
{
    while (!UART1_data_available())
    {
        /* Wait for data to be received */
    }
    /* Get and return received data from buffer */
    return UDR1;
}

void UART1_flush(void)
{
    // Tell the compiler that this variable is not being used
    unsigned char __attribute__ ((unused)) dummy;  // GCC attributes
    while ( UART1_data_available() ) dummy = UDR1;
}

/* init UART0
 * BAUD must be set and setbaud imported before calling this
 */
void UART0_init(void)
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

void UART0_putchar(unsigned char data)
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

unsigned char UART0_getchar(void)
{
    while(!UART0_data_available())
    {
        /* Wait for data to be received */
    }
    /* Get and return received data from buffer */
    return UDR0;
}

void UART0_flush(void)
{
    // Tell the compiler that this variable is not being used
    unsigned char __attribute__ ((unused)) dummy;  // GCC attributes
    while(UART0_data_available())
    {
        dummy = UDR0;
    }
}
