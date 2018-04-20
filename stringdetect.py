'''
	StringDetect
	notes:
	- Able to search program given a set list of words.
	- Word list must be speicifed in code.
	- Base64 encoded and searched as well
	
	Output:
	- Word found either by raw string or base64
	- Location
'''

#!/usr/bin/python
import r2pipe
import hashlib
import os
import argparse
import base64

filename = "/home/liam/list.txt";
r2 = r2pipe.open("/home/liam/hello.out")

r2.cmd("aaaa")

print ("STRING ENCODE SEARCH")
print ("--------------------")
with open(filename) as f:
	content = f.read().splitlines()
	for index in range(len(content)):	
		cmd = r2.cmdj("/j " + content[index]+ " 2> /dev/null")
		if cmd:
			addr= str(hex(cmd[0]["offset"]))
			string= str(cmd[0]["data"])
			print ("FOUND: "+ content[index]+ " in " + string + " was found at " + addr)
		if not cmd:
			print (content[index] + " WAS NOT FOUND.")

'''
with open(filename) as f:
	content = f.read().splitlines()
	for index in range(len(content)):
		hashContent = hashlib.md5(content[index])
		print hashContent.hexdigest()
'''

'''if not cmd:
   			print('Strings; No Hits.')
			break'''
print (" ")
print ("BASE64 ENCODE SEARCH")
print ("--------------------")
with open(filename) as f:
	content = f.read().splitlines()
	for index in range(len(content)):
		base64Encode = base64.b64encode(content[index])
		cmd = r2.cmdj("/j " + base64Encode + " 2> /dev/null")
		if cmd:
			addr= str(hex(cmd[0]["offset"]))
			string= str(cmd[0]["data"])
			print ("FOUND: "+ content[index]+ "["+base64Encode +"]"+ " in " + string + " was found at " + addr)
		if not cmd:
			print (content[index]+ "["+base64Encode +"]" + " WAS NOT FOUND.")


print (" ")
print ("BASE64 DECODE SEARCH")
print ("--------------------")




