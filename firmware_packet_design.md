# Firmware Packet Design

Header and Body are independently encrypted

Feel free to modify (but notify other teams)

## Header

Verifies user and gives information about the upcoming package and frames

 4B Verification nonce
 2B Version number
 2B Firmware size
 2B Number of body frames
 2B Number of release message frames
------------------------------------
10B Total

## Frame

Packet for data

  4B Verification nonce
256B Data
-----------------------
260B Total
