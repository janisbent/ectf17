# Firmware Packet Design

Header and Body are independently encrypted

Feel free to modify (but notify other teams)

## Header

Verifies user and gives size of firmware data

16b Verification nonce
16b Number of frames

## Body

Firmware data

16b Version number
16b Size of distribution message
DISTRIBUTION MESSAGE
16b Size of firmware
FIRMWARE - frames should come in 256 byte blocks to align with flash page size

## Frame

Max length of data is 256 bytes

16b frame length in bytes
DATA
