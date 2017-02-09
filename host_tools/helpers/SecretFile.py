#!/usr/bin/env python

"""
Represents secret_configure_output.txt. Allows for the access and writing of all values needed

"""

import os
import json

FILE_NAME = "secret_configure_output.txt"

class SecretFile:

	def __init__(self, directory):
		self.filePath = os.path.join(directory, FILE_NAME)
		self.data = {};
		self.__readDataFromFile()

	def set(self, key, value):
		self.data[key] = value

	def get(self, key):
		if key in self.data:
			return self.data[key]
		else:
			return None

	def flush(self):
		with open(self.filePath, 'w+') as file:
			file.write(json.dumps(self.data))

	def __readDataFromFile(self):
		if os.path.isfile(self.filePath):
			with open(self.filePath, 'r') as file:
				strData = file.read().replace('\n', '')

			self.data = json.loads(strData)