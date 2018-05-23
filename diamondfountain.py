'''
	https://github.com/icchy/tracecorn
	https://github.com/PyAna/PyAna

	https://rkx1209.github.io/2017/08/27/gsoc-final-report.html
	
	- emulate fs segment register for runtime API loading
	- look into de? dt? ds? dts?
	  > dts may be useful for state tracking
	  > (just see how things are done and replicate them in python)

	- command is read first before anything. obviously run init first then if
	
	- upon script initialization set a variable or something in r2 session so
	  that when invoking this script again only the pipe has to be opened
	
	- script should look at all imports and save them in a lookup table for
	  call hook to look at
	  
	- for malloc calls use aeim [address] [space] to allocate space. Save EBP 
	  and ESP beforehand then restore them right after.
	  
	- emulate TEB + PEB. initialize memory with aeim like above. Populate it with
	  mock values. Need to figure out how to load modules
	
	
	run this plugin in a r2 session like this:
	[0x00401000]> . /[path to plugin].py [args]
		
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

#   INITIALIZATION STUFF
###################################################################################
def InitPEB():
	return

'''
	Look at all symbols with 'isj' or something. Get there values and put them
	in a dictionary
'''
def InitSymbols():
	return

def InitEmu(r2, BITS=32, ARCH='x86'):
	r2.cmd('aaaa')
	r2.cmd('e io.cache=true')
	r2.cmd('e asm.bits=' + str(BITS))
	r2.cmd('e asm.arch=' + ARCH)
	r2.cmd('e asm.emu=true')
	r2.cmd('aei')
	r2.cmd('aeip')
	r2.cmd('aeim 0xFFFFD000 0x2000 stack')

def Init():
	parser = argparse.ArgumentParser()
	parser.add_argument('arg', nargs='*')
	args   = parser.parse_args()
	
	if not args.arg:
		r2 = r2pipe.open()
	else:
		r2 = r2pipe.open(os.path.realpath(args.arg[0]))
	
	return r2

#   INSTRUCTION HOOKS
###################################################################################	
def hook_call(r2, c):
	print "! Got CALL"
	
	# if call goes to API then need to lookup API in symbol dict and call its 
	# handler and-or modify the return value
	
	# call someimmediateoffset
	if 'jump' in c[0]:
		print "  > CALL IMM"
		return 0
	else:
		# call eax
		# Check whats in eax and see if it is in the symbol dictionary
		if 'reg' == c[0]['opex']['operands'][0]['type']:
			print "  > CALL REG"
			return 1
	return 1

# Hook Table
hooks = {
	'call' : hook_call,
}


#   COMMANDS
###################################################################################
def e_cont(r2):
	while True:
		r2.cmd('aes')
		insn = r2.cmdj('aoj @ eip')
		
		if insn[0]['mnemonic'] in hooks:
			ret = hooks[insn[0]['mnemonic']](r2, insn)
			if ret == 1:
				r2.cmd('s eip') # set currseek
				break
	return
	
'''
[0x401000]> . [plugin].py --command [cmd]

'''
def evalcommand():
	return

def main():
	r2 = Init()
	InitEmu(r2)
	
	# test call
	e_cont(r2)
	
	# evalcommand()
	
	# Put me in Init section
	'''
	symbols = r2.cmdj('isj')
	
	# axt - find references to some api
	usageloc = r2.cmdj('axtj @ sym.' + someapi)
	'''
	
	
	#Put me in RegOpenKey emulation function
	'''
	strarg = r2.cmd('psw @ [esp+4]')
	
	if avm_strings.susp_reg_key[0] == strarg:
		print "! @ " + hex(usageloc[0]['from']) + " VMware registry key check"
		print "  > ARG: '" + strarg + "'"
	'''
	
	r2.quit()
	
if __name__ == '__main__':
	main()
