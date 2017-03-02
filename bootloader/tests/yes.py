#!/usr/bin/env python

import serial
import argparse

parser = argparse.ArgumentParser(description='Bootloader Config Tool')
parser.add_argument('--port', help='Serial port to use for configuration.',
                    required=True)
args = parser.parse_args()

ser = serial.Serial(args.port, baudrate=115200, timeout=2) 

resp = ser.read()
while resp:
	print(resp)
	resp = ser.read()
