'''
	https://github.com/icchy/tracecorn
	https://github.com/PyAna/PyAna

	https://rkx1209.github.io/2017/08/27/gsoc-final-report.html
	
	- hook API's and modify return value
	- emulate fs segment register for runtime API loading
	- look into de? dt? ds? dts?
	  > dts may be useful for state tracking

'''

import os
import argparse
import r2pipe

class avm_strings:
	susp_reg_key = [
		'SOFTWARE\VMware, Inc.\VMware Tools',
	]
	
	susp_api = [
		'RegOpenKey',
	]

def InitEmu(r2, BITS=32, ARCH='x86'):
	r2.cmd('aaaa')
	# Enable modification of code in memory and on disk
	r2.cmd('e io.cache=true')
	r2.cmd('e asm.bits=' + str(BITS))
	r2.cmd('e asm.arch=' + ARCH)
	# Initialize ESIL VM
	r2.cmd('aei')
	# Set the starting point
	r2.cmd('aeip')
	# Initialize 0x2000 bytes of stack space at 0xFFFFD000
	r2.cmd('aeim 0xFFFFD000 0x2000 stack')

def Init():
	parser = argparse.ArgumentParser()
	parser.add_argument('arg', nargs='*')
	args   = parser.parse_args()
	
	if not args.arg:
		print "USAGE: diamondfountain.py [infile]"
		exit(1)
		
	r2 = r2pipe.open(os.path.realpath(args.arg[0]))
	
	return r2

def main():
	r2 = Init()
	InitEmu(r2)
	
	symbols = r2.cmdj('isj')
	
	for sym in symbols:
		if avm_strings.susp_api[0] in sym['name']:
			api_regopenkey = sym['name']
	
	# axt - find references of regopenkey
	usageloc = r2.cmdj('axtj @ sym.' + api_regopenkey)
	
	# emulate code until address
	r2.cmd('aesu ' + hex(usageloc[0]['from']))
	
	strarg = r2.cmd('psw @ [esp+4]')
	
	if avm_strings.susp_reg_key[0] == strarg:
		print "! @ " + hex(usageloc[0]['from']) + " VMware registry key check"
		print "  > ARG: '" + strarg + "'"
	
	r2.quit()
	
if __name__ == '__main__':
	main()
