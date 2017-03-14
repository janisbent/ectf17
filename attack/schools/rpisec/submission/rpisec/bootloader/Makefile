# Hardware configuration settings.
MCU = atmega1284p
F_CPU = 20000000
BAUD = 115200

# Secret password default value.
PASSWORD ?= password

# Tool aliases.
CC = avr-gcc
STRIP  = avr-strip
OBJCOPY = avr-objcopy
PROGRAMMER = dragon_jtag

# Compiler configurations.
# Description of CDEFS options
# -g3 -- turns on  the highest level of debug symbols.
# -ggdb3 -- turns on the highest level of debug symbols for the gdb debugger.
#
#  NOTE: The debug options shoud only affect the .elf file. Any debug symbols are stripped
#  from the .hex file so no debug info is actually loaded on the AVR. This means that removing
#  debug symbols should not affect the size of the firmware.
CDEFS = -g3 -ggdb3 -mmcu=${MCU} -DF_CPU=${F_CPU} -DBAUD=${BAUD} -DRB_PASSWORD=\"${PASSWORD}\"

# Description of CLINKER options:
# 	-Wl,--section-start=.text=0x1E000 -- Offsets the code to the start of the bootloader section
# 	-Wl,-Map,bootloader.map -- Created an additional file that lists the locations in memory of all functions.
SHITASLR  := $(shell python2 -c "import random; print(hex((random.randint(0x18000, 0x1a000))/2*2))")
SHITASLR2 := $(shell python2 -c "import random; print(hex((random.randint(0x1e000, 0x1f200))/2*2))")
CLINKER = -nostartfiles -Wl,--section-start=.text=$(SHITASLR) \
		  -Wl,--section-start=.bootloader=$(SHITASLR2) -Wl,-Map,bootloader.map

CWARN =  -Wall
COPT = -std=gnu99 -Os -fno-tree-scev-cprop -mcall-prologues \
       -fno-inline-small-functions -fsigned-char

CFLAGS  = $(CDEFS) $(CLINKER) $(CWARN) $(COPT)

# Include file paths.
INCLUDES = -I./include -I./crypto

# Run clean even when all files have been removed.
.PHONY: clean

all:    flash.hex eeprom.hex
	@echo  Simple bootloader has been compiled and packaged as intel hex.

sha2.o:
	$(CC) $(CFLAGS) $(INCLUDES) -w -c crypto/sha2.c

hmac.o:
	$(CC) $(CFLAGS) $(INCLUDES) -w -c crypto/hmac.c

ecc.o:
	$(CC) $(CFLAGS) $(INCLUDES) -w -c crypto/ecc.c

aes.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c crypto/aes.c

uart.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c include/uart.c

sys_startup.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/sys_startup.c

bootloader.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/bootloader.c

bootloader_dbg.elf: uart.o sys_startup.o bootloader.o sha2.o hmac.o aes.o ecc.o
        # Create an .elf file for the bootloader with all debug symbols included.
	$(CC) $(CFLAGS) $(INCLUDES) -o bootloader_dbg.elf uart.o sys_startup.o ecc.o bootloader.o sha2.o hmac.o aes.o

strip: bootloader_dbg.elf
	# Create a version of the bootloder .elf file with all the debug symbols stripped.
	$(STRIP) bootloader_dbg.elf -o bootloader.elf

flash.hex: strip
	$(OBJCOPY) -R .eeprom -O ihex bootloader.elf flash.hex
	avr-size flash.hex

eeprom.hex: strip
	$(OBJCOPY) -j .eeprom --set-section-flags=.eeprom="alloc,load" --change-section-lma .eeprom=0 -O ihex bootloader.elf eeprom.hex

flash: flash.hex eeprom.hex
	 avrdude -P usb -p m1284p -c $(PROGRAMMER)  -u -U flash:w:flash.hex:i \
						    -U eeprom:w:eeprom.hex:i \
						    -U lfuse:w:lfuse.hex:i \
						    -U hfuse:w:hfuse.hex:i \
						    -U efuse:w:efuse.hex:i

debug: flash.hex eeprom.hex
	# Launch avarice: a tool that creates a debug server for the AVR and Dragon
	avarice -R -g :4242 &
	# Launch the avr debugger avr-gdb. The configuation for this tool is included
	# in .gdbinit
	avr-gdb

clean:
	$(RM) -v *.hex *.o *.a *.elf *.map $(MAIN)
