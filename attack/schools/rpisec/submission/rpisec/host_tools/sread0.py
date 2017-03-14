#!/usr/bin/python2

import serial

ser = serial.Serial('/dev/ttyUSB0', baudrate=115200,timeout=2)
while True:
    s = ser.read(1024)
    if len(s) > 0:
        print("%s %s"% (s.encode('hex'), `s`))
