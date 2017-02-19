# Hardware configuration settings.
MCU = atmega1284p
F_CPU = 20000000
BAUD = 115200

# Tool aliases.
CC = avr-gcc
STRIP  = avr-strip
OBJCOPY = avr-objcopy

# Compiler configurations.
CDEFS = -mmcu=${MCU} -DF_CPU=${F_CPU} -DBAUD=${BAUD} -DPUBLIC_KEY=\"${PUBLIC_KEY}\" -DPRIVATE_KEY=\"${PRIVATE_KEY}\"
CLINKER = -nostartfiles -Wl,--section-start=.text=0x1F000
CWARN =  -Wall #-Wextra -Wformat=2 -Wformat-security
COPT = -std=gnu99 -Os -fno-tree-scev-cprop -mcall-prologues \
       -fno-inline-small-functions -fsigned-char \
#	   -Wl,--discard-all -D_FORTIFY_SOURCE=2

CFLAGS  = $(CDEFS) $(CLINKER) $(CWARN) $(COPT)

# Include file paths.
INCLUDES = -I./include #-I/usr/include/openssl

# Run clean even when all files have been removed.
.PHONY: clean

all:    flash.hex eeprom.hex
	@echo  Simple bootloader has been compiled and packaged as intel hex.

uart.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/uart.c

sys_startup.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/sys_startup.c

bootloader.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/bootloader.c

crypto.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/crypto.c

yes.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c tests/yes.c

bootloader.elf: uart.o sys_startup.o bootloader.o crypto.o
	$(CC) $(CFLAGS) $(INCLUDES) -o bootloader.elf uart.o sys_startup.o bootloader.o crypto.o

strip: bootloader.elf
	$(STRIP) bootloader.elf -o bootloader.elf

flash.hex: strip
	$(OBJCOPY) -R .eeprom -O ihex bootloader.elf flash.hex

eeprom.hex: strip
	$(OBJCOPY) -j .eeprom --set-section-flags=.eeprom="alloc,load" --change-section-lma .eeprom=0 -O ihex bootloader.elf eeprom.hex

clean:
	$(RM) -v *.hex *.o *.elf $(MAIN)

yes: uart.o yes.o
	$(CC) $(CFLAGS) $(INCLUDES) -o yes.elf uart.o yes.o
	$(STRIP) yes.elf -o yes.elf
	$(OBJCOPY) -O ihex yes.elf yes.hex
