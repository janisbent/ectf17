# Hardware configuration settings.
MCU = atmega1284p
F_CPU = 20000000
BAUD = 115200

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
CDEFS = -g3 -ggdb3 -mmcu=${MCU} -DF_CPU=${F_CPU} -DBAUD=${BAUD} -DAES_KEY="${AES_KEY}"

# Description of CLINKER options:
# 	-Wl,--section-start=.text=0x1E000 -- Offsets the code to the start of the bootloader section
# 	-Wl,-Map,bootloader.map -- Created an additional file that lists the locations in memory of all functions.
CLINKER = -Wl,--section-start=.text=0x1E000 -Wl,-Map,bootloader.map -Wl,--defsym=__heap_end=0x0

CWARN =  -Wall
COPT = -std=gnu99 -Os -fno-tree-scev-cprop -mcall-prologues \
       -fno-inline-small-functions -fsigned-char

CFLAGS  = $(CDEFS) $(CLINKER) $(CWARN) $(COPT)

# Include file paths.
INCLUDES = -I./include

# Run clean even when all files have been removed.
.PHONY: clean

all:    flash.hex eeprom.hex
	@/bin/echo
	@/bin/echo
	@/bin/echo -e "                  \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 "
	@/bin/echo -e "                  \xf0\x9f\x94\xa5 Tufts bootloader has been compiled and packaged as intel hex\xf0\x9f\x94\xa5"
	@/bin/echo -e "                  \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 \xf0\x9f\x94\xa5 "
	@/bin/echo
	@/bin/echo
	@/bin/echo -e '++ooooooooooosssssssooo++oyh+.```````````````````````````````````````````````````````````.sm++sssss+\
oooooosyyyyyyysoooooooo+yh:                                                                om+oossoo\
ssyysssoooooooooooooooodo`                                                                  hdosssss\
oooo+ooooooooooooooooomo                                                                    /Nsosssy\
ooooooooooooosssooooosN.      ..... .  . . .--.       , .--.     .--- . .   . .___          -Msssyyh\
ooooooooosssssssssssoym         |   |  | | `.         | `.       |    | |\  | |             :Mssssss\
oosysoooooooooooooooooN-        |   |``| |   `.       |   `.     |``` | | \ | |```          smosssss\
oooosyyyhhhhyhhhhhddddmd`       |   |  | | `--`       | `--`     |    | |  \| |___         .myoossss\
+oooooooosyhhhddhhysoo+yh-                                                                `hhyhddddd\
+ooo++++++++++/+++oosssosdy-                                                             -hy/++oooos\
/++++++++/++///////+/+ssooshho:`                                                      -+yh+:/oosssss\
oosoo+++oooosyhhyhyossyso+/++syhyso/:..                                         .-+oyhhyo++//+++oooo\
-::/+oooooo++/--+hhooooshdysosssssyhmdhssyyyyysssyyyys`   .-----::://////+oossyhhyss++++shdmdhyyssss\
...............sy+////////sd+:+++++/::--------------+N.  `d+/++++//://syss+++++/++++oosyhddy/+oosyys\
............../m///:////////y:.-::-...............--+m`  -m............--:+ssyyyyhhhhyo+::---+do....\
..............sh:////://oosshdssosy/.......`........sh   /h.........--....-....------.....--:d/os-.-\
...:y/........oh://oyhdmNNNNmy+:///h/...............d+  `h/........-.------.....---.....----yo--+y/:\
.-+sm:.......-/msdmNNNNNNNmy+:/://:ho`.............-N.  oo............................-----yo:---/yo\
.oo/d-.../+-ssooosyddmmmhs///:///:om/..............+d  +s..............................--/y+------.+\
o+-oh-../sod+::/:////////////://oys/oys/..........`s+`oo................`s+...........-/ss/---::+. `\
/--oy--++s+m/:/+oo++/////++oosyso/////+yy+...`...`-d-s+.................:yy:........./ss/-----:-h-`-\
---oh-/s-o++yo+/oh+ossyysso+++/////////:/yy-...`..yyo-.................:h:+y-.....-/ss/--:/----+:o::\
-:-:m:h/-:s--:/sd+////////////::::////+++/o+++/-`-+-..................:s/-:d-...-+s+:---:so---/+-:o/\
/+:-oyh:::++--/do//////+osssso+/////+s:` ./ososy:`.................../o/---d-.-+s+:----/oo/--//---:o\
//:--++:++:++hmNs////+s+:--.--:oso//s.  /dmmmmmdm-..................//-----h:/s+------++:s-:/:-----.\
::/---:/::+dmmNNd///o+`   ./++:.`/yy`  /mmmmmmmmNo..........-:://:--..-o:--shs:-----/+::-o/:-----...\
--/:-:/-:ymmmmNNm///s    +dmmmmms.-d`  hmmmmmmmmNo......`:oydmmmmmmh/-:/o-::s:----/o/---:o:------:-:\
---//:-/hNmmmmNNN+/y-   /mmmmmmmmh.h:  ymmmmmmmmm:-/+osyhNNNmmmmmmmmms--s::-----/o/--------------/-:\
---:/-ommmmmmmNMMs/d.   smmmmmmmmm+h+  -dmmmmmdmdso+++sNNNNNmmmmmmmmNh--/+----:o/---------------/:-:\
-----smNmmmmmNNMMh/s+   :mmmmmmmmmsdyo-.-/ososhy+:/:/hNNMNNNmmmmmmmmm/---o/--/o-..-----------:--+--:\
----smmmmmmmmNNMMd//h/   +mmmmmmmmdo:+osssssys+////:+NMMNNNNmmNNNNNN+-----o/:o-..-----------:--/---:\
---:mmmmmmmmmmNMMm///ys:.`-oyhdhddo/////////////////+NMMNNNNNNNNNmhd-------+s:-------------:--//---:\
---ommmmmmmmmNNMMd////+sysssssyyo////////////////////smNNMMMNNNds/y+-----..-------....----:--:/----:\
.--smmmmmmmmmNNNMy////////////////+++//////////////////osyyyso/:/ys-----.-------....-.-------/-----:\
---+NmmmmmmmmNNNN+/////////////+sssdy++///////////////////////+sho-----.------....-...-------------:\
---.hmmNNmmmNNMNo////////////ohyso.-ohdyyso++///////////+ossyys+-------.----..-----.---------------:\
-:/:/dNNNNNNNNmo////++//////+o+ysoooodd:/+hhhdhhyyyyyyhhso++/---------/----------------------------:\
yddhhdoshdddNs+/////////////////shso+yNmddmyyd/y-...`.y:--:+---------::---------::::::////:////----:\
/++od+/////yy////////////////////+shyyNNNNNNm++s-....y/--:o-.--------/--------oyyysssosooo++++ho----\
//+do++++/om+++++//+o///++++/+++////+oshhdhs++y+y/..h+---o:---------::-::-----yooyhdhhdddddddyhh/++:\
//+m+////oms+++yo++sh+++++++/+++++//////+osyhh:-:s++h---//----------/--/------s+..-/+osooo+/--/m---+\
///N/:::/hd/+++d+++yh++++++++++++++////+soo++m:-::ym/---s----------:--/:------y+..............:Nms.-\
//+M::::/Ns////m+++yd+++++++++++++++/++/+/+//sd::::o---/+---------:--//-------sy............../Nh+.-\
//sM::::+N+///+N///yd+++++++++++++++++++++++//mo:+:---:o------------//--:-----od.........-----od++os\
//sM::::oN+///+M///sm/+++++++++++++++++++++++/hd-:+:-:o:-----------::--:-----./m...-----------yhyyyy\
//sM::::oN+///+No///Mo//++++++++++++++++++++++yN:::/+++::::::::----:::-.-:/+sssmo+/::::------:m/////\
/:sN:::/+No////dh///dh//////++++++++++++++++++hm:::::/::::--::-----:+oyyyys+/:::+oosyysyyyyyyyo/////\
::sm::///dh////oN+//+mo/////////////////+++//+mo---:::::::-::::---/hNy+//////////////:://///////////\
++om/++++omooooodmoooymoooooooooooooooooooooodd::///////+/++o+///oNyhdooooooo+oo++++++++oooo++o++ooo'

uart.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/uart.c

sys_startup.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/sys_startup.c

aes.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c src/aes.c

bootloader.o: aes.o
	$(CC) $(CFLAGS) $(INCLUDES) -c src/bootloader.c

bootloader_dbg.elf: uart.o sys_startup.o bootloader.o aes.o
        # Create an .elf file for the bootloader with all debug symbols included.
	$(CC) $(CFLAGS) $(INCLUDES) -o bootloader_dbg.elf uart.o sys_startup.o bootloader.o aes.o

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

yes.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c tests/yes.c

yes: uart.o yes.o
	$(CC) $(CDEFS) $(CWARN) $(COPT) -nostartfiles $(INCLUDES) -o yes.elf uart.o yes.o
	$(STRIP) yes.elf -o yes.elf
	$(OBJCOPY) -O ihex yes.elf yes.hex

clean:
	$(RM) -v *.hex *.o *.elf $(MAIN)

