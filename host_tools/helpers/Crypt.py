#!/usr/bin/env python

"""
Deals with storage and generation of AES keys and nonce
for both factory and bootloader
"""

from SecretFile import SecretFile
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

PAGE_SIZE  = 256

class Crypt:

    def __init__(self, directory):
	   self.sf = SecretFile(directory)

    def __del__(self):
	   self.sf.flush()

    #wrapper for Crypto.Random.get_random_bytes()
    def getRandomBytes(self, num):
        return get_random_bytes(num)

    def getNonce(self):
        nonce = self.sf.getKey(self.sf.NONCE)
        if nonce is None:
            nonce = self.getRandomBytes(4)
            self.sf.setKey(self.sf.NONCE, nonce)

        return nonce

    def getAESKey(self):
        key = self.sf.getKey(self.sf.AES_KEY)
        if key is None:
            key = self.getRandomBytes(16)
            self.sf.setKey(self.sf.AES_KEY, key)

        return key

    def encode(self, msg):
        key = self.getAESKey()
        cipher = AES.new(key, AES.MODE_CBC)
        msg = self.randomPadToSize(msg, size=16)
        return (cipher.encrypt(msg), cipher.iv)

    def decode(self, msg, iv_val):
        key = self.getAESKey()
        cipher = AES.new(key, AES.MODE_CBC, iv=iv_val)
        return cipher.decrypt(msg)

    def randomPadToSize(self, msg, size=PAGE_SIZE):
        pad = len(msg) % size

        if pad == 0:
            return msg

        return msg + self.getRandomBytes(size - pad)
