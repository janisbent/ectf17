/*
 * message.h
 */

#ifndef MESSAGE_H_
#define MESSAGE_H_


/* Constants */
#define MAX_LEN 128  // the size of each frame
#define PAD_CHAR 0x06  // 0x06 is used to pad data when needed


/* Structure used to hold a message to be sent over UART */
typedef struct {
	uint8_t len;  // The length of the message to be sent
	uint8_t msg[MAX_LEN + KEY_SIZE];  // An array of characters to hold the message
} UART_msg_t;


/* Prototypes */
void send_message(UART_msg_t*);
void recv_message(UART_msg_t*, uint8_t);


#endif /* MESSAGE_H_ */
