# Secure Bootloader Code

## Host Tools

All of the host tools are in the ```host_tools``` directory. They all have the same filenames as specified in the project and are written in python.

The folder ```host_tools/utils``` holds libraries used throughout all of the host_tools. ```dce.py``` implements the crypto used throughout the whole project. 

## Bootloader

All of the bootloader code is in the ```bootloader``` directory. The bootloader can be built using the Makefile in that directory. The ```bootloader/sha1``` directory holds the C implementation of SHA1 from the avr-crypto-lib. The ```bootloader/include``` directory contains all of the header files. 

The ```bootloader/src``` directory contains the majority of the code for the bootloader. ```bootloader.c``` contains the main entry point for the bootloader. ```config.c``` holds the functions needed to instantiate and configure the cryptography used throughout the bootloader. ```crypto.c``` holds the majority of the cryptography code including the functions for arithmetic in GF(8). ```firmware.c``` holds a number of utility functions used to verify and save firmwares sent over UART. ```message.c``` contains the code to send ```UART_msg_t``` structures over serial. ```readback.c``` holds the functions used for reading back and encrypting firmware images. ```sys_startup.c``` contains code related to initializing the board. Note that this is the same as the file provided by MITRE. ```uart.c``` contains the functions used to send data over serial. Note that this is the same as the file provided by MITRE. 

### Firmware Update Steps:
1. Provisioner sends encrypted frames consisting of a constant, firmware version no, number of blocks to be sent, fw size, and new secure random. (All messages are sent with hash and verified for integrity protection.)
2. Bootloader decrypts and verifies constant and checks the validity of the version number. If valid, it sends an ok message to the provisioner.
3. The provisioner now sends the bootloader the firmware encrypted one frame at a time (128 bytes). For each frame, the bootloader decrypts the data, verifies the integrity and saves to a temporary location on the flash.
4. After the entire firmware has been received, the bootloader copies the firmware to location 0 and sends a success message to the provisioner.
5. Frames are stored in an intermediate buffer until a complete page has been sent, at which point the page is written to flash. Note that if no frame is received after 2 seconds, the bootloader will time out and reset.

### Readback Steps:
1. Provisioner sends the requested start address and size to the bootloader.
2. The bootloader responds back with a random challenge which the provisioner has to solve with the shared key in order to authenticate to the bootloader.
3. The provisioner receieves the random, hashes it with the secret key and sends the first 16 bytes of hash to the bootloader.
4. The bootloader computes the hash using the same random and its key, and matches it with the hash that was sent. If the 2 match, the user is authenticated.
5. The bootloader now reads the requested flash area one block at a time (128 bytes), encrypts it and sends to the provisioner who decrypts it for reading.

```Note:``` The Readme provides a high level description of the protocol and the low level implementation decisions are not outlined as discussed during a voice call with the organizers. These low level steps are documented in the bootloader and provision code, and it should be easy to understand the protections in place by reading the code.  