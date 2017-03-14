/*
 * UART configuration headers.
 */


#ifndef UART_H_
#define UART_H_

#include <stdbool.h>
#include <avr/boot.h>

void BOOTLOADER_SECTION UART1_init(void);

void BOOTLOADER_SECTION UART1_putchar(unsigned char data);

bool BOOTLOADER_SECTION UART1_data_available(void);
uint8_t BOOTLOADER_SECTION UART1_getchar(void);

void BOOTLOADER_SECTION UART1_flush(void);

void BOOTLOADER_SECTION UART1_getsize(uint8_t*, uint32_t);
void BOOTLOADER_SECTION UART1_getsize_progmem(uint32_t, uint32_t);

void BOOTLOADER_SECTION UART0_init(void);

void BOOTLOADER_SECTION UART0_putchar(unsigned char data);

bool BOOTLOADER_SECTION UART0_data_available(void);
uint8_t BOOTLOADER_SECTION UART0_getchar(void);

void BOOTLOADER_SECTION UART0_flush(void);

#endif /* UART_H_ */
