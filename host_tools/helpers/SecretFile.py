#!/usr/bin/env python

"""
Represents secret_configure_output.txt. Allows for the access and writing of all values needed

"""

import os
import json

FILE_NAME = "secret_configure_output.txt"

class SecretFile:

	AES_KEY = "AES"
	DSA_KEY = "DSA"

	def __init__(self, directory):
		self.filePath = os.path.join(directory, FILE_NAME)
		self.keys = dict()
		self.__readDataFromFile()

	def setKey(self, key, value):
		if self.__isValidKey(key):
			if key == self.AES_KEY:
				self.keys[key] = value.encode("hex")
			else:
				self.keys[key] = value

	def getKey(self, key):
		if self.__isValidKey(key) and key in self.keys:
			value = self.keys[key]

			if key == self.AES_KEY:
				value = value.decode("hex")

			return value
		else:
			return None

	def flush(self):
		with open(self.filePath, 'w+') as file:
			file.write(json.dumps(self.keys))

	def __isValidKey(self, key):
		return key == self.AES_KEY or key == self.DSA_KEY

	def __readDataFromFile(self):
		if os.path.isfile(self.filePath):
			with open(self.filePath, 'r') as file:
				fileStr = file.read()
				if len(fileStr) > 0:
					self.keys = json.loads(fileStr)