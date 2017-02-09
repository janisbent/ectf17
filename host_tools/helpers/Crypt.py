#!/usr/bin/env python

"""
Deals with storage and generation of both public and private keys 
for both factory and bootloader

"""

from SecretFile import SecretFile
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class Crypt:

	FACTORY_KEY = "factory_key"
	BOOTLOADER_KEY = "bootloader_key"
	NONCE = "U+1F595"

	def __init__(self, directory):
		self.sf = SecretFile(directory)

	def __del__(self):
		self.sf.flush()

	def getKey(self, keyType):
		if self._isNotKeyType(keyType):
			return None;

		encoded_key = self.sf.get(keyType)

		if encoded_key is None:
			key = RSA.generate(1024)
			self.sf.set(keyType, key.exportKey());
		else:
			key = RSA.import_key(encoded_key)
			
		return key

	def encode(self, string, fromKeyType, toKeyType):
		if self._isNotKeyType(fromKeyType) || self._isNotKeyType(toKeyType):
			return None

		privateKey = self.getKey(fromKeyType)
		publicKey = self.getKey(toKeyType).publickey()

		privateCipher = PKCS1_OAEP.new(privateKey)
		publicCipher = PKCS1_OAEP.new(publickey)

		return publicCipher.encrypt(privateCipher.encrypt(string));


	def _isNotKeyType(self, keyType):
		return keyType != self.FACTORY_KEY and keyType != self.BOOTLOADER_KEY