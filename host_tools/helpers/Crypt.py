#!/usr/bin/env python

"""
Deals with storage and generation of both public and private keys 
for both factory and bootloader

"""

from SecretFile import SecretFile
from Crypto.Cipher import AES
from Crypto.PublicKey import DSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

FRAME_SIZE = 16

PUBLIC = 1
PRIVATE = 0

class Crypt:

	def __init__(self, directory):
		self.sf = SecretFile(directory)

	def __del__(self):
		self.sf.flush()

	def getAESKey(self):
		key = self.sf.getKey(self.sf.AES_KEY)
		if key is None:
			key = get_random_bytes(16)
			self.sf.setKey(self.sf.AES_KEY, key)

		return key

	def getDSAKey(self, part=PUBLIC):
		key = self.sf.getKey(self.sf.DSA_KEY)
		if key is None:
			key = DSA.generate(1024)
			self.sf.setKey(self.sf.DSA_KEY, key.exportKey())
		else:
			key = DSA.import_key(key)

		if part == PUBLIC:
			return key.publickey()

		return key

	def hash(self, msg):
		return SHA256.new(msg).digest()

	def sign(self, msg):
		key = self.getDSAKey(part=PRIVATE)
		hashMsg = SHA256.new(msg)
		signer = DSS.new(key, 'fips-186-3')
		return signer.sign(hashMsg)

	def encode(self, msg):
		key = '1234567890123456' #self.getAESKey()
		cipher = AES.new(key, AES.MODE_ECB)
		msg = self.randomPadToSize(msg)
		return cipher.encrypt(msg)

	def decode(self, msg):
		key = '1234567890123456' #self.getAESKey()
		cipher = AES.new(key, AES.MODE_ECB)
		return cipher.decrypt(msg)

	def randomPadToSize(self, msg, size=FRAME_SIZE):
		if len(msg) > size:
			return msg

		return msg + get_random_bytes(size - len(msg))
