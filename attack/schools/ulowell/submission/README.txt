At the root level of the 2017-ectf-master.zip file should be ＆Vagrantfile＊ and three directories.
 
Firmware directory contains two files: 
1. blinkLED.c: Application firmware source code. 
2. blinkLED.hex: Original Application firmware. 
   It can be protected by Firmware Bundle-and-Protect Tool and be loaded into ATMega1284p through Firmware-Update Tool.
   It is the initial firmware on our provisioned chips and has a version number 2.

bootloader directory contains two folders and a Makefile:
1. include folder:  It contains all function header files 
   aes.h uart.h sha1.h
2. src folder: It contains bootloader source code and all function source code files
   ase.c uart.c sha1.c sys_startup.c booloader.c
3. Makefile: It used for compile the bootloader source code and generate all ralated .hex files

host_tools directory contains five tools source code and avardude.sh script:
1. bl_build: bootloader build tool. 
   Command: python bl_build
2. avardude.sh: It is a script used for AVRDUDE loading the bootloader onto ATMega1284p.
   Command: sh avardude.sh
3. bl_configure: bootloader configure tool
   We don＊t need configuration post installation of the bootloader. This tool is skipped. 
   This tool can copy all security parameters to an output file. 
   Command: python bl_configure 每port <serial prot>  e.g. python bl_configure 每port /dev/ttyUSB0
4. fw_protect: firmware protect tool
   Command: python fw_protect 每infile <unprotected_firmware_filename> --version <version_number> --message <release_message> --outfile < protected_firmware_filename >
   e.g. python fw_protect 每infile /home/ubuntu/ectf/Firmware/blinkLED.hex --version 2 --message IntFirmware --outfile SFirmware
5. fw_update: firmware update tool
   Put the jumper between the Pin PB2 to ground on Protostack board, the bootloader will enter load bootloader mode.
   Command: python fw_update 每port <serial prot> -- firmware <filename_of_protected_firmware>
   e.g. python fw_update 每port /dev/ttyUSB0 --firmware SFirmware
6. readback: readback tool
   Put the jumper between the Pin PB3 to ground on Protostack board, the bootloader will enter readback mode.
   Command: python readback 每port <serial port> --address <start_address> --num-bytes <number_of_bytes_to_read>
   e.g. python readback 每port /dev/ttyUSB0 --address 0 --num-bytes 32