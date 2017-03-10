#!/usr/bin/env python
"""
Firmware test file generator
"""

import os
import shutil
import argparse
from intelhex import IntelHex
from cStringIO import StringIO

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Firmware Generator')

    parser.add_argument("--outfile",
                        help="Filename for test firmware hex file.",
                        required=True)
    args = parser.parse_args()

    frame = ""

    for i in range(256):
        frame += chr(i)

    frame += frame

    data = ""
    for i in range(10):
        data += frame


    ih = IntelHex()
    ih.putsz(0x00, data)

    sio = StringIO()

    ih.tofile(args.outfile, format='hex')


