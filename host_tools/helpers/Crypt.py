#!/usr/bin/env python

"""
Deals with storage and generation of both public and private keys 
for both factory and bootloader

"""

from SecretFile import SecretFile
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

class Crypt:

	def __init__(self, directory):
		sf = SecretFile(directory)

		self.key = sf.getKey()
		if self.key is None:
			self.key = get_random_bytes(16)
			sf.setKey(self.key);
			sf.flush()

	def getKey(self):
		return self.key

	def hash(self, msg):
		return SHA256.new(msg).digest()

	# http://legrandin.github.io/pycryptodome/Doc/3.4/Crypto.Cipher.AES-module.html
	# msg must be multiple of 16
	def encode(self, msg):
		cipher = AES.new(self.key, AES.MODE_ECB)
		return cipher.encrypt(msg)

	def decode(self, msg):
		cipher = AES.new(self.key, AES.MODE_ECB)
		return cipher.decrypt(msg)
