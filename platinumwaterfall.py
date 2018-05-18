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
	susp_str = [
		'SOFTWARE\VMware, Inc.\VMware Tools',
		'%windir%\Sysnative\Drivers\\vmmouse.sys',
		'Vmtoolsd.exe',
	]
	
	susp_api = [
		'RegOpenKey',
		'ExpandEnvironmentStrings',
		'StrRStrIW',
		'IsDebuggerPresent'
	]

	stack_loc = [
		'[esp+4]',
		'[esp]',
		'[esp+8]',
	]

	check_type = [
		'VMware registry key check',
		'VMware file check',
		'VMware process check',
	]

def InitEmu(r2, BITS=32, ARCH='x86'):
	r2.cmd('aaaa')
	# Enable modification of code in memory and on disk
	r2.cmd('e io.cache=true')
	r2.cmd('e asm.bits=' + str(BITS))
	r2.cmd('e asm.arch=' + ARCH)
	r2.cmd('e asm.emu=true')
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
		print "USAGE: platinumwaterfall.py [infile]"
		exit(1)
		
	r2 = r2pipe.open(os.path.realpath(args.arg[0]))
	
	return r2

def EmulateAPI(r2, eax='0'):
	# Find the current instruction pointer and seek to it
	# Step over the current instruction
	# Set the instruction pointer to the current seek location
	# Set the value of the EAX register, default is 0
	r2.cmd('s `ar eip`')
	r2.cmd('so')
	r2.cmd('aeip')
	r2.cmd('ar eax=' + eax)

def main():
	r2 = Init()
	InitEmu(r2)
	startaddr = r2.cmd('s')
	symbols = r2.cmdj('isj')
	
	# What if there is more than one reference to RegOpenKey, or multiple kinds
	# of RegOpenKey functions?

	# Populate an array of full API names and the index of their short name
	# ['sym.imp.KERNEL32.dll_ExpandEnvironmentStringsW', 1] is an example entry
	api_suspicious = []
	for sym in symbols:
		for susp in avm_strings.susp_api:
			if susp in sym['name']:
				api_suspicious.append([sym['name'], avm_strings.susp_api.index(susp)])
	
	# Check to see if api_suspicious was populated with values
	if not api_suspicious:
		print "No suspicious API references detected"
		r2.quit()
		exit(0)
	else:
		print "Suspicious API reference(s) detected:"
		for susppair in api_suspicious:
			print susppair[0]
	
	# What if RegOpenKey is used more than once?
	# axt - find references of regopenkey

	for susppair in api_suspicious:
		suspapi = susppair[0]
		arrayloc = susppair[1]
		usageloc = r2.cmdj('axtj @ sym.' + suspapi)
		argloc = avm_strings.stack_loc[arrayloc]
		mesg = avm_strings.check_type[arrayloc]
		# emulate code until address
		r2.cmd('aesu ' + hex(usageloc[0]['from']))
		strarg = r2.cmd('psw @ ' + argloc)
		#print arrayloc
		#print avm_strings.susp_str[arrayloc]
		#print strarg
		if avm_strings.susp_str[arrayloc] == strarg:
			print "! @ " + hex(usageloc[0]['from']) + " " + mesg
			print "  > ARG: '" + strarg + "'"

		r2.cmd('ar0')
		r2.cmd('aeim-')
		r2.cmd('aei-')
		r2.cmd('s ' + startaddr)
		r2.cmd('aeip')
	
	r2.quit()
	
if __name__ == '__main__':
	main()
