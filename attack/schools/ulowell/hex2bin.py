#!/usr/bin/env python
"""
Intel Hex to binary
"""

import argparse
from intelhex import IntelHex


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='IntelHex to binary')

    parser.add_argument("--infile", help="Intel hex file to convert.",
                        required=True)
    parser.add_argument("--outfile", help="Output binary file.",
                        required=True)
    args = parser.parse_args()

    reader = IntelHex(args.infile)

    data = reader.tobinstr()

    print data.encode('hex')

    with open(args.outfile, 'wb+') as ofile:
    	ofile.write(data.encode('hex'))