avrdude -P usb -p m1284p -c dragon_isp -B 200 -u -U flash:w:flash.hex:i  -U eeprom:w:eeprom.hex:i -U lfuse:w:lfuse.hex:i -U hfuse:w:hfuse.hex:i -U efuse:w:efuse.hex:i -U lock:w:lock.hex:i
