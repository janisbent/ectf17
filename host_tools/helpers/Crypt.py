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
import binascii
from os import urandom

FRAME_SIZE = 16

PUBLIC = 1
PRIVATE = 0

class Crypt:

    def __init__(self, directory):
	self.sf = SecretFile(directory)

    def __del__(self):
	self.sf.flush()

    def getNonce(self):
        nonce = self.sf.getKey(self.sf.NONCE)
        if nonce is None:
            nonce = get_random_bytes(4)
            self.sf.setKey(self.sf.NONCE, nonce)

        return 0x01020304 ################## nonce

    def getAESKey(self):
        key = self.sf.getKey(self.sf.AES_KEY)
        if key is None:
            key = get_random_bytes(16)
            self.sf.setKey(self.sf.AES_KEY, key)

        return key

    def getDSAKey(self, part=PUBLIC):
        keyStr = self.sf.getKey(self.sf.DSA_KEY)
        if keyStr is None:
            key = DSA.generate(1024)
            self.sf.setKey(self.sf.DSA_KEY, key.exportKey())
        else:
            key = DSA.import_key(keyStr)

        if part == PUBLIC:
            return key.publickey()

        return key

    def getDSAKeyParts(self):
        key = self.getDSAKey()
        parts = {}
        for part in key._key:
            p = key._key[part]
            parts[part] = self.__int2bytes(p)

        return parts

    def hash(self, msg):
        return SHA256.new(msg).digest()

    def sign(self, msg):
        key = self.getDSAKey(part=PRIVATE)
        hashMsg = SHA256.new(msg)
        signer = DSS.new(key, 'fips-186-3')
        return signer.sign(hashMsg)

    def encode(self, msg):
        key = self.getAESKey()
        cipher = AES.new(key, AES.MODE_ECB)
        msg = self.randomPadToSize(msg)
        return cipher.encrypt(msg)

    def decode(self, msg):
        key = self.getAESKey()
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(msg)

    def randomPadToSize(self, msg, size=FRAME_SIZE):
        if len(msg) > size:
            return msg

        return msg + get_random_bytes(size - len(msg))

    # http://stackoverflow.com/a/28524760	
    def __int2bytes(self, i):
        hex_string = '%x' % i
        n = len(hex_string)
        return binascii.unhexlify(hex_string.zfill(n + (n & 1)))
