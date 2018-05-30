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
	
	QUESTIONS:
	- How to tell if stdcall or cdecl?
	
	TODO:
	- Do better instruction parsing. Not every command needs r2 or eapi.
	
	- Have some command to view internal data structure that we manage and be
	  able to edit them?
	
	- Build a configuration for each API (stack arguments, return values, etc)
	
	- add hooks for memory read/write/execute 
	
	- test out revolver-style task calling
	
	- PEB/TEB at offset 0x30 fs:0x30 fs is fucked so esil just accesses 0x30
	  what about the other segments like gs? on 64-bit
	  o load kernel32 and ntdll 32 and create a PEB
	 
	- SEH, fs:[0]. How the hell to detect exceptions?
	
	- Kill r2 session. Start r2 session in script.

'''

import readline
import r2pipe
#import pefile


class ApiEmu:
	susp_reg_key = [
		'SOFTWARE\VMware, Inc.\VMware Tools',
	]
	
	def __init__(self):
		self.SYMBOLS = {
			'diamond_def'              : self._DiamondDefault,
			'RegOpenKeyExW'            : self._RegOpenKeyExW,
			'RegCloseKey'              : self._RegCloseKey,
			'ExitProcess'              : self._ExitProcess,
			'GetAdaptersAddresses'     : self._GetAdaptersAddresses,
			'GetProcessHeap'           : self._GetProcessHeap,
			'HeapAlloc'                : self._HeapAlloc,
			'HeapFree'                 : self._HeapFree,
			'StrCmpNI'                 : self._StrCmpNI,
			'StrRStrIW'                : self._StrRStrIW,
			'ExpandEnvironmentStringsW': self._ExpandEnvironmentStrings,
			'FindFirstFileW'           : self._FindFirstFileW,
			'FindClose'                : self._FindClose,
			'EnumProcesses'            : self._EnumProcesses,
			'OpenProcess'              : self._OpenProcess,
			'CloseHandle'              : self._CloseHandle,
			'GetModuleFileNameExW'     : self._GetModuleFileNameExW,
			'OpenSCManagerW'           : self._OpenSCManagerW,
			'EnumServiceStatusW'       : self._EnumServiceStatusW,
			'CloseServiceHandle'       : self._CloseServiceHandle,
			'GetLastError'             : self._GetLastError,
			'wprintf'                  : self._wprintf,
			'_snwprintf'               : self.__snwprintf,
			'memset'                   : self._memset,
			'wcslen'                   : self._wcslen,
		}
		
	def _DiamondDefault(self, r2):
		print "! Unknown API"
		print r2.cmd('pd 1 @ eip')
		return

	def _GetAdaptersAddresses(self, r2):
		print "! GetAdaptersAddresses #TODO"
	def _GetProcessHeap(self, r2):
		print "! GetProcessHeap #TODO"
	def _HeapAlloc(self, r2):
		print "! HeapAlloc #TODO"
	def _HeapFree(self, r2):
		print "! HeapFree #TODO"
	def _StrCmpNI(self, r2):
		print "! StrCmpNI #TODO"
	def _StrRStrIW(self, r2):
		print "! StrRStrIW #TODO"
	def _ExpandEnvironmentStrings(self, r2):
		print "! ExpandEnvironmentStrings #TODO"
	def _FindFirstFileW(self, r2):
		print "! FindFirstFileW #TODO"
	def _FindClose(self, r2):
		print "! FindClose #TODO"
	def _EnumProcesses(self, r2):
		print "! EnumProcesses #TODO"
	def _OpenProcess(self, r2):
		print "! OpenProcess #TODO"
	def _CloseHandle(self, r2):
		print "! CloseHandle #TODO"
	def _GetModuleFileNameExW(self, r2):
		print "! GetModuleFileNameExW #TODO"
	def _OpenSCManagerW(self, r2):
		print "! OpenSCManagerW #TODO"
	def _EnumServiceStatusW(self, r2):
		print "! EnumServiceStatusW #TODO"
	def _CloseServiceHandle(self, r2):
		print "! CloseServiceHandle #TODO"
	def _GetLastError(self, r2):
		print "! GetLastError #TODO"
	def __snwprintf(self, r2):
		print "! _snwprintf #TODO"
	def _memset(self, r2):
		print "! memset #TODO"
	def _wcslen(self, r2):
		print "! wcslen #TODO"
		
	def _RegOpenKeyExW(self, r2):
		print "! RegOpenKeyExW"
		
		strarg = r2.cmd('psw @ [esp+4]')
		
		if strarg in ApiEmu.susp_reg_key:
			print "! VMware registry key check"
		
		print "  > ARG: '" + strarg + "'"
		
		r2.cmd('ar eax=0')
		
		return
	
	def _RegCloseKey(self, r2):
		print "! RegCloseKey"
		r2.cmd('ar eax=0')
		return
		
	def _ExitProcess(self, r2):
		print "! ExitProcess"
		return
		
	def _wprintf(self, r2):
		print "! _wprintf #TODO"
		r2.cmd('ar eax=0')
		return

#   COMMAND FUNCTIONS
###################################################################################
def Build_TEB_PEB(r2, eapi=None):
	
	EBP = r2.cmd('ar ebp')
	ESP = r2.cmd('ar esp')
	
	r2.cmd('aeim 0x0 0x40')      # for fs:[0x30] or fs:[0]
	r2.cmd('aeim 0x1000 0x1000') # for PEB
	
	# use wv to write addresses
	r2.cmd('wv 0x1000 @ 0x30')
	
	# TODO: finish inner PEB structures
	# TODO: map kernel32 + ntdll + kernelbase.
	
	return

SYMBOLS = { }

def BuildSymbols(r2, eapi):
	for symbol in r2.cmdj('isj'):
		content = r2.cmdj('pxrj 4 @ ' + hex(symbol['vaddr']))
		for i, API in enumerate(eapi.SYMBOLS):
			if API in symbol['flagname']:
				print "Got: " + API
				SYMBOLS[content[0]['value']] = eapi.SYMBOLS[API]
				i = 0
				break
		if i == len(eapi.SYMBOLS) - 1:
			print "Unknown API: " + symbol['flagname']
			SYMBOLS[content[0]['value']] = eapi.SYMBOLS['diamond_def']
	
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
		addr = int(r2.cmd('s'), 0)
		
		if addr in SYMBOLS:
			r2.cmd('.ar-; ar eip=[esp]; ar esp=esp+4')
			SYMBOLS[addr](r2)
			break
		
		insn = r2.cmdj('aoj @ eip')
		
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
			r2.cmd('-ar* ; ar0 ; aeim- ; aei-;')
			r2.quit() # doesn't always quit for some reason. Use pkill r2.
			break
		
		if command in COMMANDS:
			COMMANDS[command](r2, eapi) # do better instruction parsing
		else:
			print r2.cmd(command)



	
if __name__ == '__main__':
	main()
