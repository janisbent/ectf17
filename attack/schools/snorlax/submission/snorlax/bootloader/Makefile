# Hardware configuration settings.
MCU = atmega1284p
F_CPU = 20000000
BAUD = 115200

# Tool aliases.
CC = avr-gcc
STRIP  = avr-strip
OBJCOPY = avr-objcopy

KEY1 ?= key1
KEY2 ?= key2

# Compiler configurations.
CDEFS = -mmcu=${MCU} -DF_CPU=${F_CPU} -DBAUD=${BAUD} -DSKEY1=${KEY1} -DSKEY2=${KEY2}
CLINKER = -nostartfiles -Wl,--section-start=.rel_ver=0x7800,--section-start=.rel_msg=0x7900,--section-start=.text=0x1E000,--section-start=.skey1=0x1FFE0,--section-start=.skey2=0x1FFF0
# CLINKER = -nostartfiles -Wl,--section-start=.text=0x1F000
CWARN =  -Wall
COPT = -std=gnu99 -Os -fno-tree-scev-cprop -mcall-prologues \
       -fno-inline-small-functions -fsigned-char

CFLAGS  = $(CDEFS) $(CLINKER) $(CWARN) $(COPT)

# Include file paths.
INCLUDES = -I./include

# Run clean even when all files have been removed.
.PHONY: clean

all:    flash.hex eeprom.hex
	@echo  Simple bootloader has been compiled and packaged as intel hex.

f.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/norx/f.S

norx.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/norx/norx.c

uart.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/uart.c

sys_startup.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/sys_startup.c

bootloader.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/bootloader.c

bootloader.elf: uart.o sys_startup.o bootloader.o norx.o f.o
	$(CC) $(CFLAGS) $(INCLUDES) -o bootloader.elf uart.o sys_startup.o bootloader.o norx.o f.o

strip: bootloader.elf
	$(STRIP) bootloader.elf -o bootloader.elf

flash.hex: strip
	$(OBJCOPY) -R .eeprom -O ihex bootloader.elf flash.hex

eeprom.hex: strip
	$(OBJCOPY) -j .eeprom --set-section-flags=.eeprom="alloc,load" --change-section-lma .eeprom=0 -O ihex bootloader.elf eeprom.hex

clean:
	$(RM) -v *.hex *.o *.elf $(MAIN)

