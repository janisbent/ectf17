#!/usr/bin/env python
"""
Serial port echo tool

"""

import argparse
import sys
import serial

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Serial Port Readback Tool')

    parser.add_argument("--port", help="Serial port to listen to",
                        required=True)
    args = parser.parse_args()

    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    print('Opening serial port...')
    ser = serial.Serial(args.port, baudrate=9600, timeout=2) 

    # Read data
    while True:
        sys.stdout.write(ser.read().encode('hex'))
        #sys.stdout.write(ser.read())
        sys.stdout.flush()

