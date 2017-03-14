This directory contains five tools source code and avardude.sh script:
1. bl_build: bootloader build tool. 
   Command: python bl_build
2. avrdude.sh: It is a script used for AVRDUDE loading the bootloader onto ATMega1284p.
   Command: sh avardude.sh
3. bl_configure: bootloader configure tool
   We don＊t need configuration post installation of the bootloader. So this tool is skipped.
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