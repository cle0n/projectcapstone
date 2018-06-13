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
	- How to tell if stdcall or cdecl? Can't
	
	TODO:
	- Do better instruction parsing. Not every command needs r2 or eapi.
	
	- Have some command to view internal data structure that we manage and be
	  able to edit them?

	- continue making API defs
	
	- add hooks for memory read/write/execute 
	
	- test out revolver-style task calling

	- Figure out which instructions radare2 can't emulate and emulate them
	  - cpuid, bt, cdq
	
	- SEH, fs:[0]. How the hell to detect exceptions? Can't without extensive analysis

	- add breakpoints?

'''

import psutil
import readline
import r2pipe
import pefile
import sys


class ApiEmu:
	ret_stk = []
	CONTEXT = {}

	susp_reg_key = [
		'SOFTWARE\VMware, Inc.\VMware Tools',
	]

	susp_api = [
		'ShellExecuteA', 'ShellExecuteW',
		'AdjustTokenPriveleges',
		'CheckRemoteDebuggerPresent',
		'OleGetClipboard',
		'GetCommandLineA', 'GetCommandLineW',
		'TlsGetValue',
		'IsDebuggerPresent',
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
			'GetSystemTimeAsFileTime'  : self._GetSystemTimeAsFileTime,
			'GetCurrentProcessId'      : self._GetCurrentProcessId,
			'GetCurrentThreadId'       : self._GetCurrentThreadId,
			'GetTickCount'             : self._GetTickCount,
			'QueryPerformanceCounter'  : self._QueryPerformanceCounter,
			'LoadLibraryA'             : self._LoadLibraryA,
			'GetProcAddress'           : self._GetProcAddress,
			'SetErrorMode'             : self._SetErrorMode,
			'GetModuleFileNameA'       : self._GetModuleFileNameA,
			'GetCurrentDirectoryA'     : self._GetCurrentDirectoryA,
			'GetComputerNameA'         : self._GetComputerNameA,
			'GetFileAttributesA'       : self._GetFileAttributesA,
			'TlsGetValue'              : self._TlsGetValue,
			'GlobalUnfix'              : self._GlobalUnfix,
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
		print "! HeapAlloc #TODO"
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
	
	def _GetFileAttributesA(self, r2):
		print "! GetFileAttributesA"
		print "  > ARG: '" + r2.cmd('ps @ [esp]') + "'"
		r2.cmd('ar esp=esp+4')
		r2.cmd('ar eax=0x80') # return FILE_ATTRIBUTE_NORMAL by default
	
	def _GetComputerNameA(self, r2):
		print "! GetComputerNameA"
		cname = r"DESKTOP-570DAJQ"
		print "  > Using dummy data: " + cname
		loc = r2.cmdj('pxwj 4 @ esp')
		r2.cmd('wz ' + cname + ' @ ' + hex(loc[0]))
		r2.cmd('ar esp=esp+8')
		r2.cmd('ar eax=1')
	
	def _GetCurrentDirectoryA(self, r2):
		print "! GetCurrentDirectoryA"
		dummy = r"C:\\Users\\Dummy\\Desktop"
		print "  > Using dummy data: " + dummy
		loc   = r2.cmdj('pxwj 4 @ esp+4')
		r2.cmd('wz ' + dummy + ' @ ' + hex(loc[0]))
		r2.cmd('ar esp=esp+8')
		r2.cmd('ar eax=' + hex(len(dummy) - 4))
	
	def _GetModuleFileNameA(self, r2):
		print "! GetModuleFileNameA"
		dummy = r"C:\\Users\\Dummy\\Desktop\\dumb.exe"
		print "  > Using dummy data: " + dummy
		loc   = r2.cmdj('pxwj 4 @ esp+4')
		r2.cmd('wz ' + dummy + ' @ ' + hex(loc[0]))
		r2.cmd('ar esp=esp+12')
		r2.cmd('ar eax=' + hex(len(dummy) - 5))
	
	def _SetErrorMode(self, r2):
		print "! SetErrorMode"
		r2.cmd('ar esp=esp+4')
		r2.cmd('ar eax=1')
	
	def _GetProcAddress(self, r2):
		print "! GetProcAddress"
		API = r2.cmd('ps @ [esp+4]')
		print "  > ARG: '" + API + "'"
		r2.cmd('ar esp=esp+8')

		# get rid of the try-catch
		for sym in SYMBOLS:
			try:
				if SYMBOLS[sym] == self.SYMBOLS[API]:
					r2.cmd('ar eax=' + hex(sym))
					break
			except KeyError:
				pass
	
	def _LoadLibraryA(self, r2):
		print "! LoadLibraryA #TODO"
		print "  > ARG: '" + r2.cmd('ps @ [esp]') + "'"
		r2.cmd('ar esp=esp+4')
		r2.cmd('ar eax=0x77FD0000')
		
	def _RegOpenKeyExW(self, r2):
		print "! RegOpenKeyExW"
		
		strarg = r2.cmd('psw @ [esp+4]')
		
		if strarg in ApiEmu.susp_reg_key:
			print "! VMware registry key check"
		
		print "  > ARG: '" + strarg + "'"
		
		r2.cmd('ar eax=0')
	
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
	
	def _TlsGetValue(self, r2):
		print "! TlsGetValue"
		r2.cmd('ar esp=esp+4')
		r2.cmd('ar eax=1')
	
	def _GlobalUnfix(self, r2):
		print "! GlobalUnfix"
		r2.cmd('ar esp=esp+4')
		r2.cmd('ar eax=1')

#   COMMAND FUNCTIONS
###################################################################################
def BuildInMemoryModules(r2, eapi=None, args=None):
	EBP = r2.cmd('ar ebp')
	ESP = r2.cmd('ar esp')

	# init TIB
	r2.cmd('aeim 0x0 0x1000')
	# write PEB pointer
	r2.cmd('wv 0x100 @ 0x30')
	# write Ldr pointer
	r2.cmd('wv 0x200 @ 0x10C')
	# write InMemoryOrderModuleList
	r2.cmd('wv 0x300 @ 0x214')
	# write ntdll node
	r2.cmd('wv 0x400 @ 0x300')
	# write kernel32 node
	r2.cmd('wv 0x500 @ 0x400')
	# write kernel32 base
	r2.cmd('wv 0x74FF0000 @ 0x510')

	k32 = pefile.PE('./DLLS/_kernel32.dll')

	base = 0x74FF0000

	ExpDirRVA = k32.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
	ExpDir    = base + ExpDirRVA

	NumberOfFunctions     = k32.DIRECTORY_ENTRY_EXPORT.struct.NumberOfFunctions
	AddressOfNames        = base + k32.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames
	AddressOfFunctions    = base + k32.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions
	AddressOfNameOrdinals = base + k32.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNameOrdinals
	NameRVA               = 0x100000
	NamesTable            = base + NameRVA

	r2.cmd('aeim ' + hex(base) + ' 0x1000')

	r2.cmd('aeim ' + hex(AddressOfNameOrdinals) + ' ' + hex(NumberOfFunctions * 2))
	r2.cmd('aeim ' + hex(AddressOfFunctions)    + ' ' + hex(NumberOfFunctions * 4))
	r2.cmd('aeim ' + hex(AddressOfNames)        + ' ' + hex(NumberOfFunctions * 4))
	r2.cmd('aeim ' + hex(NamesTable)            + ' ' + '0x30000')
	r2.cmd('aeim ' + hex(ExpDir)                + ' ' + '0x28')

	r2.cmd('yf 4096 0x0 DLLS/_kernel32.dll')
	r2.cmd('yy 0x74FF0000')
	r2.cmd('yf 40 ' + hex(k32.get_offset_from_rva(ExpDirRVA)) + ' DLLS/_kernel32.dll')
	r2.cmd('yy '    + hex(ExpDir))
	
	print "! Mapping Exports"
	i = 0
	# fix the -3 ordinal adjustment.
	for exp in k32.DIRECTORY_ENTRY_EXPORT.symbols:
		r2.cmd('wv2 ' + str(exp.ordinal - 3) + ' @ ' + hex(AddressOfNameOrdinals + (i * 2))) 
		r2.cmd('wv4 ' + hex(exp.address) + ' @ ' + hex(AddressOfFunctions    + (i * 4)))
		r2.cmd('wv4 ' + hex(NameRVA)     + ' @ ' + hex(AddressOfNames        + (i * 4)))
		r2.cmd('wz '  + exp.name         + ' @ ' + hex(NamesTable))

		if exp.name in eapi.SYMBOLS:
			SYMBOLS[exp.address + base] = eapi.SYMBOLS[exp.name]

		namelen     = len(exp.name) + 1
		NamesTable += namelen
		NameRVA    += namelen
		i += 1

	r2.cmd('.ar-')
	r2.cmd('ar ebp=' + EBP)
	r2.cmd('ar esp=' + ESP)
	
	return

SYMBOLS = { }

def BuildSymbols(r2, eapi, args=None):
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

def InitEmu(r2, eapi=None, args=None):
	BITS ='32'
	ARCH ='x86'

	# > init a e b
	for arg in args:
		if arg == 'a':
			r2.cmd('aaaa')
		elif arg == 'e':
			r2.cmd('e io.cache=true')
			r2.cmd('e asm.bits=' + BITS)
			r2.cmd('e asm.arch=' + ARCH)
			r2.cmd('e asm.emu=true')
			r2.cmd('aei')
			r2.cmd('aeip')
			r2.cmd('aeim 0x60C000 0x32000 stack')
		elif arg == 'b':
			BuildSymbols(r2, eapi)

def Continue(r2, eapi, args=None):
	count     = 1
	stepcount = sys.maxsize
	
	if args:
		if isinstance(args, list):
			try:
				count = int(args[0])
				print '! Continuing', args[0], 'times'
			except ValueError:
				print '! INVALID ARGUMENT'
				return
		else:
			stepcount = args
	
	while count > 0:
		while stepcount:
			addr = int(r2.cmd('s'), 0)
			
			if addr in SYMBOLS:
				r2.cmd('.ar-; ar eip=[esp]; ar esp=esp+4')
				SYMBOLS[addr](r2)
				eapi.ret_stk.pop() # API emulations pop their own return addr
				break
			
			insn = r2.cmdj('aoj @ eip')

			if insn[0]['mnemonic'] in IHOOKS:
				ret = IHOOKS[insn[0]['mnemonic']](r2, insn, eapi)
				if ret == 1:
					break

			for op in insn[0]['opex']['operands']:
				if 'disp' and 'segment' in op and op['segment'] == 'fs':
					print "! FS:0 detected. Adjust manually before continuing."
					r2.cmd('aes; s eip')
					return

			r2.cmd('aes')
			stepcount -= 1

		count -= 1
		r2.cmd('s eip')

def Step(r2, eapi=None, args=None):
	if args:
		try:
			count = int(args[0])
		except ValueError:
			print "! INVALID ARGUMENT"
			return
	else:
		count = 1

	Continue(r2, eapi, count)

def Stop(r2, eapi=None, args=None):
	r2.cmd('-ar* ; ar0 ; aeim- ; aei-;')
	r2.quit()

	for proc in psutil.process_iter():
		if proc.name() == 'r2':
			proc.terminate()
	
	exit(0)

def Api(r2, eapi=None, args=None):
	for symbol in r2.cmdj('isj'):
		for API in ApiEmu.susp_api:
			if API in symbol['flagname']:
				print "!", API

def String(r2, eapi=None, args=None):
	with open(args[0].strip('"')) as f:
		content = f.readlines()
	
	for index in xrange(len(content)):
		res = r2.cmdj('/j ' + content[index] + ' 2> /dev/null') # /dev/null is linux specific
		if res:
			print "!", content[index], "at", hex(res[0]['offset']) + ": " + res[0]['data']
		else:
			print "!", content[index], "NOT FOUND"
	
	for index in xrange(len(content)):
		b64 = base64.b64encode(content[index])
		res = r2.cmdj('/j ' + b64 + ' 2> /dev/null')
		if res:
			print "! Base64", content[index], "at", hex(res[0]['offset']) + ": " + res[0]['data']
		else:
			print "! Base64", content[index], "NOT FOUND"

def Help(r2=None, eapi=None, args=None):
	HELP = """COMMANDS:
	init [aeb] - Initializes ESIL VM
	             a = analyze, e = emulation, b = symbols (separate with spaces)
	symb       - Builds list of imports links known ones to our emulated API's
	loadmod    - Builds mock TIB/PEB and loads kernel32.dll export info 
	api        - Get a list of Suspicious APIs in the malware
	string [x] - Searches malware for suspicious looking strings
	             x = filename/path in double-quotes
	cont [x]   - Continue Emulation
	             x = number of times to continue (default=1)
	step [x]   - Analyzed Step
	             x = number of times to step (default=1)
	stop       - Exit and kill r2
	help       - Display this help"""
	print HELP

COMMANDS = {
	'init'   : InitEmu,
	'symb'   : BuildSymbols,
	'loadmod': BuildInMemoryModules,
	'api'    : Api,
	'string' : String,
	'cont'   : Continue,
	'step'   : Step,
	'stop'   : Stop,
	'help'   : Help,
}

#   INSTRUCTION HOOK CALLBACKS
#
#   The last thing each hook should do is single step
###################################################################################
def HOOK_CALL(r2, insn, eapi):
	# don't care what kind of call.
	expected_ret_val = hex(insn[0]['addr'] + insn[0]['size'])
	eapi.ret_stk.append(expected_ret_val)
	print "! EXPECTED RETURN: " + expected_ret_val
	r2.cmd('s eip')
	print r2.cmd('pd 1')
	r2.cmd('aes')
	return 1

def HOOK_RET(r2, insn, eapi):
	ret_val = hex(r2.cmdj('pxwj @ esp')[0])
	print "! RET " + ret_val
	if eapi.ret_stk:
		expected_ret_val = eapi.ret_stk.pop()
		if expected_ret_val != ret_val:
			print "! UNEXPECTED RETURN (LIKELY STACK MANIPULATION)"
			print "  > EXPECTED: " + expected_ret_val
			print "  > ACTUAL  : " + ret_val
		else:
			print "! VALID RETURN"
	r2.cmd('aes')
	return 1

def HOOK_BT(r2, insn, eapi):
	ecx_val = int(r2.cmd('ar ecx'), 0)
	if ecx_val == eapi.CONTEXT['CPUID']['ecx']:
		print "! ECX UNCHANGED SINCE LAST CPUID CALL"
		btInstrDetails = r2.cmdj('aoj @ eip')[0]
		if (
			btInstrDetails['opex']['operands'][0]['type']  == 'reg' and
			btInstrDetails['opex']['operands'][0]['value'] == 'ecx' and
			btInstrDetails['opex']['operands'][1]['type']  == 'imm' and
			btInstrDetails['opex']['operands'][1]['value'] == 31
		):
			print "! 31st bit of ECX being checked"
			print "! VM DETECTION CODE FOUND"
	r2.cmd('aes')
	return 1

def HOOK_CPUID(r2, insn, eapi):
	eax_val = int(r2.cmd('ar eax'), 0)
	if eax_val == 1:
		print "! CPUID RUN WHERE EAX = 1"
		r2.cmd('aes')
		ecx_val = int(r2.cmd('ar ecx'), 0)
		eapi.CONTEXT['CPUID'] = {
			'eax': eax_val,
			'ecx': ecx_val,
		}
	else:
		r2.cmd('aes')
	return 1

IHOOKS = {
	'call' : HOOK_CALL,
	'ret'  : HOOK_RET,
	'cpuid': HOOK_CPUID,
	'bt'   : HOOK_BT,
	#'cdq'  : HOOK_CDQ,
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
		
		if not command:
			continue

		scommand = command.split()

		if scommand[0] in COMMANDS:
			COMMANDS[scommand[0]](r2, eapi, scommand[1:])
		else:
			print r2.cmd(command)


	
if __name__ == '__main__':
	main()
