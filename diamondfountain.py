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
	*Can't use pipes :(
	*Also can't use semi-colons with our personal commands
	
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
import random
import sys
import time
import os
#import pefile


class ApiEmu:
	ret_stk = []
	CONTEXT = {}

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
			'GetModuleFileNameA'	   : self._GetModuleFileNameA,
			'OpenSCManagerW'           : self._OpenSCManagerW,
			'EnumServiceStatusW'       : self._EnumServiceStatusW,
			'CloseServiceHandle'       : self._CloseServiceHandle,
			'GetLastError'             : self._GetLastError,
			'wprintf'                  : self._wprintf,
			'_snwprintf'               : self.__snwprintf,
			'memset'                   : self._memset,
			'wcslen'                   : self._wcslen,
           		'GetSystemTimeAsFileTime'  : self._GetSystemTimeAsFileTime,
            		'GetCurrentProcessId'      : self._GetCurrentProcessId,
		        'GetCurrentThreadId'       : self._GetCurrentThreadId,
        		'GetTickCount'             : self._GetTickCount,
        		'QueryPerformanceCounter'  : self._QueryPerformanceCounter,
			'LoadLibraryA'		   : self._LoadLibraryA,
			'GetProcAddress'	   : self._GetProcAddress,
			'SetErrorMode'		   : self._SetErrorMode,
			'GetCurrentDirectoryA'	   : self._GetCurrentDirectoryA,
			'TlsGetValue'		   : self._TlsGetValue,
			'GlobalUnfix'		   : self._GlobalUnfix,
		}
		
	def _DiamondDefault(self, r2):
		print "! Unknown API"
		print r2.cmd('pd 1')
		return

	def _GetAdaptersAddresses(self, r2):
		print "! GetAdaptersAddresses #TODO"
	def _GetProcessHeap(self, r2):
		print "! GetProcessHeap #TODO"
	def _HeapAlloc(self, r2):
		print "! HeapAlloc"
		r2.cmd("ar esp=esp+12")
		r2.cmd("ar eax=1")
		return

	def _HeapFree(self, r2):
		print "! HeapFree #TODO"
	def _StrCmpNI(self, r2):
		print "! StrCmpNI #TODO"
	def _ExpandEnvironmentStrings(self, r2):
		print "! ExpandEnvironmentStrings #TODO"
	def _FindFirstFileW(self, r2):
		print "! FindFirstFileW #TODO"
	def _FindClose(self, r2):
		print "! FindClose #TODO"
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
	def _GetSystemTimeAsFileTime(self, r2):
		print "! GetSystemTimeAsFileTime"
		r2.cmd('ar esp=esp+4')

	def _GetCurrentProcessId(self, r2):
		print "! GetCurrentProcessId"
		r2.cmd('ar eax=1')

	def _GetCurrentThreadId(self, r2):
		print "! GetCurrentThreadId"
		r2.cmd('ar eax=1')

	def _GetTickCount(self, r2):
		print "! GetTickCount"
		r2.cmd('ar eax=1')

	def _QueryPerformanceCounter(self, r2):
		print "! QueryPerformanceCounter"
		r2.cmd('ar esp=esp+4')
		r2.cmd('ar eax=1')
		
	def _OpenProcess(self, r2):
		print "! OpenProcess"
		r2.cmd('ar esp=esp+12')
		r2.cmd('ar eax=1111')

	def _CloseHandle(self, r2):
		print "! CloseHandle"
		r2.cmd('ar esp=esp+4')
		r2.cmd('ar eax=1')

	def _GetModuleFileNameExW(self, r2):
		print "! GetModuleFileNameExW"
		r2.cmd('ar esp=esp+12')
		r2.cmd('ar eax=1')

	def _StrRStrIW(self, r2):
		print "! StrRStrIW"
		print "  > ARG: " + r2.cmd('psw @ [esp+8]')
		r2.cmd('ar esp=esp+12')
		r2.cmd('ar eax=1')

	def _EnumProcesses(self, r2):
		print "! EnumProcesses"
		r2.cmd('wv 0x666 @ [esp]')
		r2.cmd('wv 0x4 @ [esp+8]')
		r2.cmd('ar esp=esp+12')
		r2.cmd('ar eax=1')

	def _LoadLibraryA(self, r2):
		print "! LoadLibrary"
		r2.cmd("ar esp=esp+4")
		r2.cmd("ar eax=1")
		return

	def _GetProcAddress(self, r2):
		print "! GetProcAddress"
		r2.cmd("ar esp=esp+8")
		r2.cmd("ar eax=1")
		return

	def _SetErrorMode(self, r2):
		print "! SetErrorMode"
		r2.cmd("ar esp=esp+4")
		r2.cmd("ar eax=1")
		return

	def _GetModuleFileNameA(self, r2):
		print "! GetModuleFileNameA"
		r2.cmd("ar esp=esp+12")
		r2.cmd("ar eax=1")
		return

	def _GetCurrentDirectoryA(self, r2):
		print "! GetCurrentDirectoryA"
		r2.cmd("ar esp=esp+8")
		r2.cmd("ar eax=1")
		return

	def _TlsGetValue(self, r2):
		print "! TlsGetValue"
		r2.cmd('ar esp=esp+4')
		r2.cmd('ar eax=1')
		return

	def _GlobalUnfix(self, r2):
		print "! GlobalUnfix"
		r2.cmd('ar esp=esp+4')
		r2.cmd('ar eax=1')
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
	f
	# TODO: finish inner PEB structures
	# TODO: map kernel32 + ntdll + kernelbase.
	
	return

SYMBOLS = { }

def BuildSymbols(r2, eapi, dummy0=None):
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

def InitEmu(r2, eapi=None, dummy0=None, BITS=32, ARCH='x86'):
	# Actual init stuff
	r2.cmd('e anal.bb.maxsize=16384')
	r2.cmd('aaaa')
	r2.cmd('e io.cache=true')
	r2.cmd('e asm.bits=' + str(BITS))
	r2.cmd('e asm.arch=' + ARCH)
	r2.cmd('e asm.emu=true')
	r2.cmd('aei')
	r2.cmd('aeip')
	r2.cmd('aeim 0xFFFFD000 0x32000 stack')
	# Cause we always run symb anyway
	BuildSymbols(r2, eapi)

	# Make sure cont doesn't skip the first instruction!
	# Don't need breaks cause we're not in a loop
	# Don't want any seeking ('aes', 's eip') so cont works properly 
	addr = int(r2.cmd('s'), 0)
	
	if addr in SYMBOLS:
		r2.cmd('.ar-; ar eip=[esp]; ar esp=esp+4')
		SYMBOLS[addr](r2)
	
	insn = r2.cmdj('aoj @ eip')
	
	if insn[0]['mnemonic'] in IHOOKS:
		IHOOKS[insn[0]['mnemonic']](r2, insn, eapi)


def Continue(r2, eapi=None, args=None):
	count = 1
	if args:
		try:
			count = int(args[0])
		except ValueError:
			print "Invalid argument"
			return
	while count > 0:	
		while True:
			# Found a bit of a subtle bug here.
			# If the very first instruction should be hooked
			# it would've been skipped by the aes command
			# before we could analyze it.
			r2.cmd('aes')
			addr = int(r2.cmd('s'), 0)
		
			if addr in SYMBOLS:
				r2.cmd('.ar-; ar eip=[esp]; ar esp=esp+4')
				SYMBOLS[addr](r2)
				break
		
			insn = r2.cmdj('aoj @ eip')
		
			if insn[0]['mnemonic'] in IHOOKS:
				ret = IHOOKS[insn[0]['mnemonic']](r2, insn, eapi)
				if ret == 1:
					break

			for op in insn[0]['opex']['operands']:
			    if 'disp' and 'segment' in op and op['segment'] == 'fs':
				print "! FS:0 detected. Adjust manually before continuing."
				r2.cmd('s eip')
				break # Used to be return
		count -= 1
		r2.cmd('s eip')

def Api(r2, eapi=None, args=None):
	BadAPIs = {"ShellExecuteA", "AdjustTokenPrivileges", 
		   "CheckRemoteDebuggerPresent", "OleGetClipboard", 
		   "GetCommandLineA", "TlsGetValue", 
		   "Swaggertester", "IsDebuggerPresent"}

	for symbol in r2.cmdj('isj'):
		for APIs in BadAPIs:	
			if APIs in symbol['flagname']:			
				print APIs

def Str(r2, eapi=None, args=None):
	print "Hello."	
	
	r2 = r2pipe.open("/home/liam/Desktop/e67aa9da71042fe85d03b7f57c18e611d3d16167ca9f86615088f2fd98b17a99copy")
	filename = "/home/liam/list.txt";


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


def Help(dummy0=None, dummy1=None, dummy2=None):
	HELP = """COMMANDS:
	init - Initializes ESIL VM
	symb - Builds list of imports links known ones to our emulated API's
	cont - Continue Emulation
	api  - Get a list of Suspicious APIs in the malware.
	str  - Searches malware for malisious looking strings.
	stop - Exit and stop r2
	help - Display this help"""
	print HELP
	

COMMANDS = {
	'symb': BuildSymbols,
	'init': InitEmu,
	'cont': Continue,
	'api': Api,
	'string': Str,
	'help': Help,
}

#   INSTRUCTION HOOK CALLBACKS
###################################################################################
def HOOK_CALL(r2, insn, eapi):
	if 'jump' in insn[0]:
		r2.cmd('s eip') # Might need this for an annoying bug...
		print "! CALL " + hex(insn[0]['jump'])
		
		# When a call is made add the expected return value to the stack
		expected_ret_val = hex(r2.cmdj('aoj 2')[-1]['addr'])
		print "! EXPECTED RETURN " + expected_ret_val
		if not r2.cmdj('pdfj @ ' + hex(insn[0]['jump'])):
			print "! INVALID FUNCTION CALL"
		eapi.ret_stk.append(expected_ret_val)

	# Turns out there are other kinds of calls that aren't being properly checked
	# Stuff like call dword [0x41f004] for instance
	if 'ptr' in insn[0]:
		if int(insn[0]['ptr']) in SYMBOLS:
			return 1

		r2.cmd('s eip') # Might need this for an annoying bug...
		print "! CALL " + hex(insn[0]['ptr'])
		
		# When a call is made add the expected return value to the stack
		expected_ret_val = hex(r2.cmdj('aoj 2')[-1]['addr'])
		print "! EXPECTED RETURN " + expected_ret_val
		if not r2.cmdj('pdfj @ ' + hex(insn[0]['ptr'])):
			print "! INVALID FUNCTION CALL"
		else:
			eapi.ret_stk.append(expected_ret_val)

	if 'reg' in insn[0]:
		r2.cmd('s eip') # Might need this for an annoying bug...
		print "! CALL " + r2.cmd('ar ' + insn[0]['reg'])
		
		# When a call is made add the expected return value to the stack
		expected_ret_val = hex(r2.cmdj('aoj 2')[-1]['addr'])
		print "! EXPECTED RETURN " + expected_ret_val
		if not r2.cmdj('pdfj @ ' + r2.cmd('ar ' + insn[0]['reg'])):
			print "! INVALID FUNCTION CALL"
		else:
			eapi.ret_stk.append(expected_ret_val)
	
		
	return 1
def HOOK_RET(r2, insn, eapi):
	ret_val = hex(r2.cmdj('pxwj @ esp')[0]) # This is the actual return value
	print "! RET " + ret_val
	# Check for expected return addresses, if there aren't any then
	# we hit a RET instruction without a CALL instruction
	if eapi.ret_stk:
		expected_ret_val = eapi.ret_stk.pop()
		if expected_ret_val != ret_val:
			print "! UNEXPECTED RETURN (LIKELY STACK MANIPULATION)"
			print "EXPECTED: " + expected_ret_val
			print "ACTUAL: " + ret_val
		else:
			print "! VALID RETURN"
	else:
		print "! UNEXPECTED RETURN (RET WITHOUT CALL)"
	return 1

def HOOK_CPUID(r2, insn, eapi):
	eax_val = int(r2.cmd("ar eax"), 16) # Get value of EAX before CPUID call
	if eax_val == 1:
		print "! CPUID RUN WHILE EAX == 1"
		r2.cmd("aes")
		ecx_val = int(r2.cmd("ar ecx"), 16) # Get value of ECX after CPUID call, this could cause bugs like cont missing an instruction...
		eapi.CONTEXT['CPUID'] = {'eax': eax_val, 'ecx': ecx_val}
	return 1

def HOOK_BT(r2, insn, eapi):
	ecx_val = int(r2.cmd("ar ecx"), 16)
	if ecx_val == eapi.CONTEXT['CPUID']['ecx']:
		print "! ECX UNCHANGED SINCE LAST CPUID CALL"
		btInstrDetails = r2.cmdj("aoj @ eip")[0]
		if (
			btInstrDetails["opex"]["operands"][0]["type"] == "reg" and 
			btInstrDetails["opex"]["operands"][0]["value"] == "ecx" and
			btInstrDetails["opex"]["operands"][1]["type"] == "imm" and
			btInstrDetails["opex"]["operands"][1]["value"] == 31
		):
			print "! 31ST BIT OF ECX BEING CHECKED"
			print "! VM DETECTION CODE FOUND"
	return 1

IHOOKS = {
	'call' : HOOK_CALL,
	'ret'  : HOOK_RET,
	'cpuid': HOOK_CPUID,
	'bt'   : HOOK_BT,
}

#   MAIN
###################################################################################
def main():
	
	os.system("gnome-terminal -e 'bash -c \"killall -9 r2; r2 -qc=h ~/Desktop/e67aa9da71042fe85d03b7f57c18e611d3d16167ca9f86615088f2fd98b17a99copy\" '")
		
	time.sleep(1);
	
	r2   = r2pipe.open('http://127.0.0.1:9090')
	eapi = ApiEmu()
	bro = random.choice(['Bruh', 'Bro', 'Breh', 'Brah', 'Broseph', 'Brocahontas', 'Brometheous'])
	print r2.cmd('?E ' + bro)
	print "Enter help for a list of commands."

	while True:
		try:
			commandAndArgs    = raw_input('[' + r2.cmd('s') + ']> ')
		except EOFError:
			print '[' + r2.cmd('s') + ']> '
			commandAndArgs    = sys.stdin.readline()
		commandAndArgsArr = commandAndArgs.split()
		command           = commandAndArgsArr[0]
		args = []		
		if len(commandAndArgsArr) > 1:
			args      = commandAndArgsArr[1:]

		if command == "stop":
			r2.cmd('-ar* ; ar0 ; aeim- ; aei-;')
			r2.quit() # doesn't always quit for some reason. Use pkill r2.
			break
		
		if command in COMMANDS:
			COMMANDS[command](r2, eapi, args) # do better instruction parsing
		else:
			print r2.cmd(commandAndArgs)


	
if __name__ == '__main__':
	main()
