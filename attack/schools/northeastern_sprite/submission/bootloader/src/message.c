/*
 * message.c
 */

#include <avr/wdt.h>
#include "uart.h"
#include "sha1.h"
#include "crypto.h"
#include "message.h"

/**
 * Send a message to the uart interface
 */
void send_message(UART_msg_t *uart_msg) {
	for (uint8_t i = 0; i < uart_msg->len; i++) {
		UART1_putchar(uart_msg->msg[i]);
		uart_msg->msg[i] = 0;

		wdt_reset();
	}
}

/**
 * Receive a message from the uart interface
 */
void recv_message(UART_msg_t *uart_msg, uint8_t len) {
	uart_msg->len = len;
	for (uint8_t i = 0; i < uart_msg->len; i++) {
		uart_msg->msg[i] = 0;
		uart_msg->msg[i] = UART1_getchar();

		wdt_reset();
	}
}

