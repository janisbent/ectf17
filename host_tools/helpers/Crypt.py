#!/usr/bin/env python

"""
Deals with storage and generation of both public and private keys 
for both factory and bootloader

"""

from SecretFile import SecretFile
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

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

		if encoded_key is None:
			key = RSA.generate(4096)
			self.sf.set(keyType, key.exportKey());
		else:
			key = RSA.import_key(encoded_key)
			
		return key

	def getKeys(self):
		return (self.getKey(self.FACTORY_KEY), self.getKey(self.BOOTLOADER_KEY))

	def encode(self, msg):
		factoryKey, bootloaderKey = self.getKeys();

		cipher = PKCS1_OAEP.new(bootloaderKey.publickey())
		signer = pkcs1_15.new(factoryKey)

		cryptMsg = cipher.encrypt(msg)
		msgHash = SHA256.new(cryptMsg)

		return signer.sign(msgHash) + cryptMsg;

	def decode(self, msg):
		factoryKey, bootloaderKey = self.getKeys();

		msgHash = msg[:512]
		cryptMsg = msg[512:]

		cryptMsgHash = SHA256.new(cryptMsg)	

		try:
			pkcs1_15.new(factoryKey.publickey()).verify(cryptMsgHash, msgHash)
			cipher = PKCS1_OAEP.new(bootloaderKey)
			return cipher.decrypt(cryptMsg)
		except (ValueError, TypeError):
			print "The signature is not valid."


	def _isNotKeyType(self, keyType):
		return keyType != self.FACTORY_KEY and keyType != self.BOOTLOADER_KEY`