#include <avr/io.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <util/delay.h>
#include <avr/boot.h>
#include <avr/wdt.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#include <util/delay.h>

#include "uart.h"



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

	while (1) {
		UART1_putchar('Y');
		_delay_ms(1);
		UART1_putchar('\n');
		_delay_ms(1);
	}
}
