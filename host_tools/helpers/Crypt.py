#!/usr/bin/env python

"""
Deals with storage and generation of both public and private keys 
for both factory and bootloader

"""

from SecretFile import SecretFile
from Crypto.PublicKey import RSA

class Crypt:

	FACTORY_KEY = "factory_key"
	BOOTLOADER_KEY = "bootloader_key"

	def __init__(self, directory):
		self.sf = SecretFile(directory)

	def __del__(self):
		self.sf.flush()

	def getKey(self, keyType):
		if self._isNotKeyType(keyType):
			return None;

		encoded_key = self.sf.get(keyType)

		if not encoded_key is None:
			key = RSA.import_key(encoded_key)
		else:
			key = RSA.generate(1024)
			self.sf.set(keyType, key.exportKey());
			
		return key


	def _isNotKeyType(self, keyType):
		return keyType != self.FACTORY_KEY and keyType != self.BOOTLOADER_KEY