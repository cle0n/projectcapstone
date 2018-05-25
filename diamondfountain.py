'''
	Steps:
	
	- In one terminal do:
	$ r2 -qc=h program.exe
	
	This starts r2 on a local webserver
	
	- In another terminal do:
	$ python diamondfountain.py
	
	This connects to r2 on local webserver

	*Visual Mode not supported.
	*Certain r2 commands won't work
	
	
	TODO:
	- For API calls, need to determine how many arguments were pushed on the
	  stack so we can adjust it accordingly after emulation. (assuming cdecl)
	- How to determine if cdecl or stdcall? Let user decide? what if obfuscated?
	- What if CALL -> JMP like wprintf?? ( Monitor EIP instead of CALL insn )
	- Do better instruction parsing. Not every command needs r2 or eapi.
	- Have some command to view internal data structure that we manage and be
	  able to edit them?
	- Build a configuration for each API (stack arguments, return values, etc)

'''

import r2pipe


class ApiEmu:
	susp_reg_key = [
		'SOFTWARE\VMware, Inc.\VMware Tools',
	]
	
	def __init__(self):
		self.SYMBOLS = {
			'RegOpenKeyExW': self._RegOpenKeyExW,
			'RegCloseKey'  : self._RegCloseKey,
			'ExitProcess'  : self._ExitProcess,
			'_wprintf'     : self.__wprintf,
		}
		
	def _RegOpenKeyExW(self, r2):
		print "RegOpenKeyExW"
		r2.cmd('.ar-; ar eip=[esp]; ar esp=esp+4')
		
		strarg = r2.cmd('psw @ [esp+4]')
		
		if strarg in ApiEmu.susp_reg_key:
			print "! VMware registry key check"
			print "  > ARG: '" + strarg + "'"
		
		r2.cmd('ar eax=0')
		
		return
	
	def _RegCloseKey(self, r2):
		print "RegCloseKey"
		r2.cmd('.ar-; ar eip=[esp]; ar esp=esp+4')
		r2.cmd('ar eax=0')
		return
		
	def _ExitProcess(self, r2):
		print "ExitProcess"
		r2.cmd('.ar-; ar eip=[esp]; ar esp=esp+4')
		return
		
	def __wprintf(self, r2):
		print "_wprintf"
		r2.cmd('.ar-; ar eip=[esp]; ar esp=esp+4')
		r2.cmd('ar eax=0')
		return

#   COMMAND FUNCTIONS
###################################################################################
def Build_TEB_PEB(r2, eapi):
	return

SYMBOLS = { }

def BuildSymbols(r2, eapi):
	for symbol in r2.cmdj('isj'):
		content = r2.cmdj('pxrj 4 @ ' + hex(symbol['vaddr']))
		for API in eapi.SYMBOLS:
			if API in symbol['flagname']:
				SYMBOLS[content[0]['value']] = eapi.SYMBOLS[API]
	
	#usageloc = r2.cmdj('axtj @ sym.' + someapi)

def InitEmu(r2, eapi=None, BITS=32, ARCH='x86'):
	r2.cmd('aaaa')
	r2.cmd('e io.cache=true')
	r2.cmd('e asm.bits=' + str(BITS))
	r2.cmd('e asm.arch=' + ARCH)
	r2.cmd('e asm.emu=true')
	r2.cmd('aei')
	r2.cmd('aeip')
	r2.cmd('aeim 0xFFFFD000 0x2000 stack')

def Continue(r2, eapi=None):
	while True:
		r2.cmd('aes')
		insn = r2.cmdj('aoj @ eip')

		# check if EIP is in API hooks list instead--or in addtion to CALL?
		
		if insn[0]['mnemonic'] in IHOOKS:
			ret = IHOOKS[insn[0]['mnemonic']](r2, insn)
			if ret == 1:
				break
	r2.cmd('s eip')

def Help(dummy0=None, dummy1=None):
	HELP = """COMMANDS:
	init - Initializes ESIL VM
	symb - Builds list of imports links known ones to our emulated API's
	cont - Continue Emulation
	stop - Exit and stop r2
	help - Display this help"""
	print HELP

COMMANDS = {
	'symb': BuildSymbols,
	'init': InitEmu,
	'cont': Continue,
	'help': Help,
}

#   INSTRUCTION HOOK CALLBACKS
###################################################################################
def HOOK_CALL(r2, insn):
	if 'jump' in insn[0]:
		print "! CALL " + hex(insn[0]['jump'])
	else:
		# step into the CALL
		r2.cmd('aes')
		addr = int(r2.cmd('s'), 16)
		if addr in SYMBOLS:
			SYMBOLS[addr](r2)
		else:
			r2.cmd('.ar-; ar eip=[esp]; ar esp=esp+4')
			# adjust sp and ip to recover from effects of the CALL
			# does not account for arguments on stack! 
		
	return 1

IHOOKS = {
	'call' : HOOK_CALL,
}

#   MAIN
###################################################################################
def main():
	r2   = r2pipe.open('http://127.0.0.1:9090')
	eapi = ApiEmu()
	
	print r2.cmd('?E Bruh')
	print "Enter help for a list of commands."

	while True:
		command = raw_input('[' + r2.cmd('s') + ']> ')
		
		if command == "stop":
			r2.quit() # doesn't always quit for some reason. Use pkill r2.
			break
		
		if command in COMMANDS:
			COMMANDS[command](r2, eapi) # do better instruction parsing
		else:
			print r2.cmd(command)



	
if __name__ == '__main__':
	main()
