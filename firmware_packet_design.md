# Firmware Packet Design

Header and Body are independently encrypted

Feel free to modify (but notify other teams)

## Header

Verifies user and gives size of firmware data

16b verification nonce
16b size of firmware

## Body

Firmware data

16b Version number
16b Size of distribution message
DISTRIBUTION MESSAGE
16b size of firmware
FIRMWARE
