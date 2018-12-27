#!/usr/bin/env python

'''
this script can help you when analysing python related PE or pythonscript format file
created by rofmia
and other features such as deconfusion will be supported later
'''


import os, os.path
import pefile
import marshal
import zipfile
import StringIO
import argparse

from uncompyle6.main import decompile



"""
flag returns a vlaue that stand for diffent file_format
0	not PE file
1	Py2exe file
2	PyInstaller file
3	pyc file
4	PYTHONSCRIPT binary stream"""


class PythonExecutable_parse(object):

	def __init__(self, filename, check_option = False):
		self.python_version = 0.0

		if os.path.exists(filename):
			self.filename = filename
			self.check = check_option
			self.fptr = open(filename, "rb")
		else:
			raise Exception("File not found")
			sys.exit(1)


	def executable_check(self):

		try:
			pe_file = pefile.PE(self.filename)
		except:
			#check for PYTHONSCRIPT format
			file_data = self.fptr.read()
			if b'\x12\x34\x56\x78' == file_data[:4]:
				return ("PYTHONSCRIPT", file_data)
				#can not support for python 3.x currently
			else:
				return ("NOT_PE", None)

		#check for py2exe foamrt file 
		if hasattr(pe_file, "DIRECTORY_ENTRY_RESOURCE"):
			for entry in pe_file.DIRECTORY_ENTRY_RESOURCE.entries:
				#get python script version from pythonx.x.dll
				if str(entry.name).endswith(".DLL"):
					self.python_version = int(str(entry.name)[6:8])
				if str(entry.name) == "PYTHONSCRIPT":
					script_resourse = entry.directory.entries[0].directory.entries[0]
					if script_resourse != None:
						pythonscript = pe_file.get_data(script_resourse.data.struct.OffsetToData, script_resourse.data.struct.Size)
			return ("PY2EXE", pythonscript)

		#check for pyinstaller encode PE file
		#pass


		#check for pyc file
		#pass


	def fclose(self):
		try:
			self.fptr.close()
		except Exception as e:
			pass



def Decompilepy2exe(rsrc_data, version = 2.7):

    offset = rsrc_data[16:].find("\x00")
    if offset == -1:
        return
    pythoncode = marshal.loads(rsrc_data[16 + offset + 1:])
    oStringIO = StringIO.StringIO()
    decompile(version, pythoncode[-1], oStringIO)
    return oStringIO.getvalue()



if __name__ =="__main__":

	print os.getcwd()
	parser = argparse.ArgumentParser(description = "this script can help you detect or unpack python-binary file such as py2exe and pyinstaller.")
	parser.add_argument("-i", "--input", dest="input", required=True, action="store", help="pyscript file or binary file packed with py2exe or pyinstaller")
	parser.add_argument("-o", "--output", dest="output", required=False, action="store", help="folder you pointed to store decompiled script.")
	parser.add_argument("-c", "--check", dest="check", required=False, action="store_true", default=False, help="that helps you to check what your binary file encoded with")
	args = parser.parse_args()
	file_name 		= args.input
	output_dir_name = args.output
	check_option 	= args.check

	if file_name is not None:
		a = PythonExecutable_parse(file_name)
		py_metadata = a.executable_check()
		a.fclose()

		if check_option == True:
			print "%s is a %s file"%(file_name, py_metadata[0])

		if output_dir_name is not None:
			if py_metadata[0] == "PYTHONSCRIPT":
				#not support for pythonscript version check currently
				pyscript = Decompilepy2exe(py_metadata[1], 2.7)
				#print pyscript
			elif py_metadata[0] == "PY2EXE":
				pyscript = Decompilepy2exe(py_metadata[1], a.python_version/ 10.0)
				#print pyscript

			if os.path.exists(output_dir_name):
				open(os.path.join(output_dir_name, "decode_script.py"), "w").write(pyscript)
			else:
				os.system("mkdir %s"%output_dir_name)
				open(os.path.join(output_dir_name, "decode_script.py"), "w").write(pyscript)
