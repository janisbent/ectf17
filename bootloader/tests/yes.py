#!/usr/bin/env python

import serial

ser = serial.Serial(args.port, baudrate=115200, timeout=2) 

resp = ser.read()
while resp:
	print(resp)
	resp = ser.read()