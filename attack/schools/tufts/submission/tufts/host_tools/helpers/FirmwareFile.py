from zipfile import ZipFile
import json

# Encode the data as json and write to outfile.
    
class FirmwareFile:

	METADATA_FILENAME = "metadata"

	def __init__(self, firmwareFileName):
		self.firmwareFileName = firmwareFileName
		self.curFileName = ['a']

	def __iter__(self):
		with ZipFile(self.firmwareFileName, 'r') as zf:
			fileList = zf.namelist()
			fileList.sort(key=lambda item: (len(item), item))

			for filename in fileList:
				if filename != self.METADATA_FILENAME:
					data = json.loads(zf.read(filename))
					data['msg'] = data['msg'].decode('hex')
					data['iv'] = data['iv'].decode('hex')
					yield data

	def __len__(self):
		byteSize = 0

		with ZipFile(self.firmwareFileName, 'r') as zf:
			for fileInfo in zf.infolist():
				byteSize += fileInfo.file_size

		return byteSize

	def filecount(self):
		with ZipFile(self.firmwareFileName, 'r') as zf:
			return len(zf.namelist())

	def getMetadata(self):
		with ZipFile(self.firmwareFileName, 'r') as zf:
			metadata = zf.read(self.METADATA_FILENAME)
		
		metadata = json.loads(metadata, encoding="ascii")	
                print metadata
		metadata['header'] = metadata['header'].decode('hex')
		metadata['iv'] = metadata['iv'].decode('hex')
		return metadata

	def writeMetadata(self, header, version, size, iv):
		data = {
        	'header'   : header.encode('hex'),
        	'version'  : version,
        	'size'     : size,
        	'iv'       : iv.encode('hex')
    	}
    	
		self.__writeData(self.METADATA_FILENAME, data)

	def writePage(self, msg, iv):
		data = {
			'msg' : msg.encode('hex'),
			'iv'  : iv.encode('hex')
		}
		filename = ''.join(self.curFileName)
		self.__writeData(filename, data)
		self.__incrementFilename()


	def __writeData(self, fileName, data):
		data = json.dumps(data, encoding="ascii")

		with ZipFile(self.firmwareFileName, 'a') as zf:
			zf.writestr(fileName, data)

	def __incrementFilename(self):
		aCount = 0

		for i in range(len(self.curFileName) - 1, -1, -1):
			if self.curFileName[i] == 'z':
				self.curFileName[i] = 'a'
				aCount += 1
			else:
				self.curFileName[i] = chr(ord(self.curFileName[i]) + 1)
				break

		if aCount == len(self.curFileName):
			self.curFileName.append('a')
