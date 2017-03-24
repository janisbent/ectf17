#!/usr/bin/env python
"""
Hacking tools for Northeastern
"""

import struct
import os
import argparse

from Crypto.Hash import SHA

BLOCK_SIZE = 16
HEADER_OFFSET = 8
RAND_SIZE = 16
HEADER_SIZE = BLOCK_SIZE + RAND_SIZE
HASH_SIZE = 16
BODY_OFFSET = HEADER_OFFSET + HASH_SIZE + HEADER_SIZE
MSG_SIZE = 128 
FRAME_SIZE = HASH_SIZE + MSG_SIZE

pa = '~\xf0Y\xe0\xd3\x84\xe5$\xe4\x9e\x97_\x9d\xbe>\x8a'  # Public constant a
pb = '#\x12\xbb/\xa0(\xa9\xd0[5\x89}\xfb\xe6^\xf7'  # Public constant b

def xor(m1, m2):
    res = []
    for i in range(len(m1)):
        res.append(chr(ord(m1[i]) ^ ord(m2[i])))
    return "".join(res)

def first_block_key(data):
	start = HEADER_OFFSET + HASH_SIZE
	end = start + BLOCK_SIZE
	enc_block = data[start:end]

	const = "DECC"
	size = struct.unpack(">I", data[:4])[0]
	version = data[4:8]
	no_frames = (len(data) - BODY_OFFSET) / (MSG_SIZE + HASH_SIZE)
	no_frames = struct.pack(">I", no_frames)
	dec_block = const + no_frames + version + data[:4]
	key = xor(enc_block, dec_block)

	print "Decrypted header: " + dec_block.encode('hex')
	print "Encrypted header: " + enc_block.encode('hex')
	print "             Key: " + key.encode('hex')

	return key

def crack_key(fwFile, outfile):

	with open(fwFile, 'rb') as f:
		data = f.read()

	key = first_block_key(data).encode('hex')

	with open(outfile, 'wb') as outfile:
		outfile.write(key)

def encrypt(fwFile, keyFile, outfile):
	return

def get_next_key(block_key):
    sha = SHA.new()
    sha.update(block_key)
    sha.update(pa)
    return sha.digest()[:16]

def strip_hashes(raw_data):
	# Get header
	start = HASH_SIZE
	end = start + HEADER_SIZE
	enc_data = raw_data[start:end]

	# Seperate date from hash
	for i in range(BODY_OFFSET, len(raw_data), FRAME_SIZE):
		start = i + HASH_SIZE
		end = start + MSG_SIZE
		enc_data += raw_data[start:end]

	return enc_data

def decrypt(fwFile, keyFile, outfile):
	
	with open(fwFile, 'rb') as fwf:
		raw_data = fwf.read()[HEADER_OFFSET:]
	with open(keyFile, 'rb') as kf:
		key = kf.read().decode('hex')

	enc_data = strip_hashes(raw_data)

	print enc_data.encode('hex')
	dec_data = xor(enc_data[:BLOCK_SIZE], key)
	block_key = get_next_key(key)
	print dec_data.encode('hex')

	sha1 = SHA.new()
	sha1.update(block_key)
	sha1.update(pb)
	key = sha1.digest()[:16]

	for i in range(BLOCK_SIZE, len(enc_data), BLOCK_SIZE):

		block = xor(enc_data[i:i + BLOCK_SIZE], key)

		print block.encode('hex')
		dec_data += block

		# set the new block key
		block_key = get_next_key(block_key)

		sha = SHA.new()
		sha.update(block_key)
		sha.update(pb)
		key = sha.digest()[:16]

	with open(outfile, 'wb') as of:
		of.write(dec_data)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Northeastern code cracker')
	group = parser.add_mutually_exclusive_group(required=True)

	group.add_argument('-c','--crack-key',action='store',nargs=2,dest='crackKey',
					   help='Crack the first block key from encrypted firmware image.',
					   metavar=("EncFirmware","Outfile"))
	group.add_argument('-e','--encrypt',action='store',nargs=3,dest='encrypt',
					   help='Encrypt firmware using first block key.',
					   metavar=("Firmware", "Key", "Outfile"))
	group.add_argument('-d','--decrypt',action='store',nargs=3,dest='decrypt',
					   help='Decrypt protected firmware image using first block key.',
					   metavar=("EncFirmware","Key","Outfile"))

	args = parser.parse_args()

	if args.crackKey:
		crack_key(args.crackKey[0], args.crackKey[1])
	elif args.encrypt:
		encrypt(args.encrypt[0], args.encrypt[1], args.encrypt[2])
	else:
		decrypt(args.decrypt[0], args.decrypt[1], args.decrypt[2])


	





