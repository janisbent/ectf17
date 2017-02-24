#!/usr/bin/env python

"""
Represents secret_configure_output.txt. Allows for the access and writing of all values needed

"""

import os

FILE_NAME = "secret_configure_output.txt"

class SecretFile:

	def __init__(self, directory):
		self.filePath = os.path.join(directory, FILE_NAME)
		self.key = None
		self.__readDataFromFile()

	def setKey(self, value):
		self.key = value

	def getKey(self):
		return self.key

	def flush(self):
		with open(self.filePath, 'w+') as file:
			file.write(self.key)

	def __readDataFromFile(self):
		if os.path.isfile(self.filePath):
			with open(self.filePath, 'r') as file:
				strData = file.read()

			self.key = strData