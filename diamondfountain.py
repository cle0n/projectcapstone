'''
	Main

'''

import subprocess
import psutil
import readline
import r2pipe
import pefile
import os
import time
import sys
import base64

from voyager1 import Voyager
from emuinfo  import EmuInfo

FNULL = open(os.devnull, 'w')

#   COMMAND FUNCTIONS
###################################################################################
def BuildInMemoryModules(emuinfo, args=None):
	EBP = emuinfo.r2.cmd('ar ebp')
	ESP = emuinfo.r2.cmd('ar esp')

	# init TIB
	emuinfo.r2.cmd('aeim 0x0 0x1000')
	# write PEB pointer
	emuinfo.r2.cmd('wv 0x100 @ 0x30')
	# write Ldr pointer
	emuinfo.r2.cmd('wv 0x200 @ 0x10C')
	# write InMemoryOrderModuleList
	emuinfo.r2.cmd('wv 0x300 @ 0x214')
	# write ntdll node
	emuinfo.r2.cmd('wv 0x400 @ 0x300')
	# write kernel32 node
	emuinfo.r2.cmd('wv 0x500 @ 0x400')
	# write kernel32 base
	emuinfo.r2.cmd('wv 0x74FF0000 @ 0x510')

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

	emuinfo.r2.cmd('aeim ' + hex(base) + ' 0x1000')

	emuinfo.r2.cmd('aeim ' + hex(AddressOfNameOrdinals) + ' ' + hex(NumberOfFunctions * 2))
	emuinfo.r2.cmd('aeim ' + hex(AddressOfFunctions)    + ' ' + hex(NumberOfFunctions * 4))
	emuinfo.r2.cmd('aeim ' + hex(AddressOfNames)        + ' ' + hex(NumberOfFunctions * 4))
	emuinfo.r2.cmd('aeim ' + hex(NamesTable)            + ' ' + '0x30000')
	emuinfo.r2.cmd('aeim ' + hex(ExpDir)                + ' ' + '0x28')

	emuinfo.r2.cmd('yf 4096 0x0 DLLS/_kernel32.dll')
	emuinfo.r2.cmd('yy 0x74FF0000')
	emuinfo.r2.cmd('yf 40 ' + hex(k32.get_offset_from_rva(ExpDirRVA)) + ' DLLS/_kernel32.dll')
	emuinfo.r2.cmd('yy '    + hex(ExpDir))
	
	print "! Mapping Exports"
	i = 0
	# fix the -3 ordinal adjustment.
	for exp in k32.DIRECTORY_ENTRY_EXPORT.symbols:
		emuinfo.r2.cmd('wv2 ' + str(exp.ordinal - 3) + ' @ ' + hex(AddressOfNameOrdinals + (i * 2))) 
		emuinfo.r2.cmd('wv4 ' + hex(exp.address) + ' @ ' + hex(AddressOfFunctions    + (i * 4)))
		emuinfo.r2.cmd('wv4 ' + hex(NameRVA)     + ' @ ' + hex(AddressOfNames        + (i * 4)))
		emuinfo.r2.cmd('wz '  + exp.name         + ' @ ' + hex(NamesTable))

		if exp.name in emuinfo.SYMBOLHOOKS:
			emuinfo.SYMBOLS[exp.address + base] = emuinfo.SYMBOLHOOKS[exp.name]

		namelen     = len(exp.name) + 1
		NamesTable += namelen
		NameRVA    += namelen
		i += 1

	emuinfo.r2.cmd('.ar-')
	emuinfo.r2.cmd('ar ebp=' + EBP)
	emuinfo.r2.cmd('ar esp=' + ESP)
	
def BuildSymbols(emuinfo, args=None):
	print "! Building Symbols"
	unknown = 0
	for symbol in emuinfo.r2.cmdj('isj'):
		content = emuinfo.r2.cmdj('pxrj 4 @ ' + hex(symbol['vaddr']))
		for i, API in enumerate(emuinfo.SYMBOLHOOKS):
			if API in symbol['flagname']:
				print " Got: " + API
				emuinfo.SYMBOLS[content[0]['value']] = emuinfo.SYMBOLHOOKS[API]
				i = 0
				break
		if i == len(emuinfo.SYMBOLHOOKS) - 1:
			#print "Unknown API: " + symbol['flagname']
			emuinfo.SYMBOLS[content[0]['value']] = emuinfo.SYMBOLHOOKS['diamond_def']
			unknown += 1

	print "! UNKNOWN API's: " + str(unknown)
	
	#usageloc = r2.cmdj('axtj @ sym.' + someapi)

def InitEmu(emuinfo, args):
	BITS = '32'
	ARCH = 'x86'

	if not args:
		print "Requires arguements. See help."
	else:
		# > init a e b
		for arg in args:
			if arg == 'a':
				print "! Running analysis: aaaa"
				emuinfo.r2.cmd('aaaa') # test timeout setting
				print "! Initializing Voyager"
				emuinfo.voy = Voyager(emuinfo.r2)
			elif arg == 'e':
				print "! Initializing Emulator"
				emuinfo.r2.cmd('e io.cache=true')
				emuinfo.r2.cmd('e asm.bits=' + BITS)
				emuinfo.r2.cmd('e asm.arch=' + ARCH)
				emuinfo.r2.cmd('e asm.emu=true')
				emuinfo.r2.cmd('aei')
				emuinfo.r2.cmd('aeip')
				emuinfo.r2.cmd('aeim 0x60C000 0x32000 stack')
			elif arg == 'b':
				BuildSymbols(emuinfo)
			elif arg == 'r':
				emuinfo.ret_stk = []
				emuinfo.jmp_stk = {
					'count': {},
					'order': [],
				}
				emuinfo.CONTEXT       = {}
				emuinfo.loop_detected = False
				emuinfo.voy           = None
				emuinfo.ctf           = False

def Continue(emuinfo, args=None):
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
			addr = int(emuinfo.r2.cmd('s'), 0)
			
			if addr in emuinfo.SYMBOLS:
				emuinfo.r2.cmd('.ar-; ar eip=[esp]; ar esp=esp+4')
				emuinfo.SYMBOLS[addr](emuinfo)
				if emuinfo.ret_stk:
					emuinfo.ret_stk.pop() # API emulations pop their own return addr
				break
			
			insn = emuinfo.r2.cmdj('aoj @ eip')
			if not insn:
				print "Invalid instruction reached! Automatic analysis cannot continue."
				emuinfo.ctf = False
				break

			if insn[0]['mnemonic'] in emuinfo.IHOOKS:
				ret = emuinfo.IHOOKS[insn[0]['mnemonic']](emuinfo, insn)
				if ret == 1:
					break

			for op in insn[0]['opex']['operands']:
				if 'disp' and 'segment' in op and op['segment'] == 'fs':
					print "! FS:0 detected. Adjust manually before continuing."
					emuinfo.r2.cmd('aes; s eip')
					if not emuinfo.ctf:
						return
					else:
						break

			emuinfo.r2.cmd('aes')
			stepcount -= 1

		count -= 1
		emuinfo.r2.cmd('s eip')

def ContinueTilFail(emuinfo, args=None):
	if not emuinfo:
		print "Not initialized"
		return 1
	emuinfo.ctf = True
	if args:
		Continue(emuinfo, args)
		emuinfo.ctf = False
	else:
		while emuinfo.ctf:
			Continue(emuinfo, 1) #was args instead of 1 before
	return 0

def Step(emuinfo, args=None):
	if args:
		try:
			count = int(args[0])
		except ValueError:
			print "! INVALID ARGUMENT"
			return
	else:
		count = 1

	Continue(emuinfo, count)

def Stop(emuinfo, args=None):
	emuinfo.r2.cmd('-ar* ; ar0 ; aeim- ; aei-;')
	emuinfo.r2.quit()

	FNULL.close()

	# Try and fix this so it doesn't kill all the r2 sessions
	for proc in psutil.process_iter():
		if proc.name() == 'r2':
			proc.terminate()
	
	exit(0)

def Api(emuinfo, args=None):
	for symbol in emuinfo.r2.cmdj('isj'):
		for API in emuinfo.susp_api:
			if API in symbol['flagname']:
				print "! SUSPICIOUS: ", API

def String(emuinfo, args=None):
	#izzj automatically encodes strings into base64, because radare2 hates its users
	for string in emuinfo.r2.cmdj('izzj')['strings']:
		#print string
		if not args:
			for susp_string in emuinfo.susp_string + emuinfo.susp_reg_key:
				#print "Checking against " + base64.b64decode(string['string'])
				if susp_string in base64.b64decode(string['string']):
					print "! FOUND ", susp_string, "at", hex(string['vaddr']) + ": " + base64.b64decode(string['string'])
				if base64.b64encode(susp_string) == base64.b64decode(string['string']):
					print "! Base64 ENCODING FOUND ", susp_string, "at", hex(string['vaddr']) + ": " + base64.b64decode(string['string'])
				else:
					if args in base64.b64decode(string['string']):
						print "! FOUND ", args, "at", hex(string['vaddr']) + ": " + base64.b64decode(string['string'])
					if base64.b64encode(args) == base64.b64decode(string['string']):
						print "! Base64 ENCODING FOUND ", args, "at", hex(string['vaddr']) + ": " + base64.b64decode(string['string'])

'''
def String(emuinfo, args=None):
	#Can't display mutiple finds.
	for index in xrange(len(emuinfo.susp_string)):
		res = emuinfo.r2.cmdj('/j ' + emuinfo.susp_string[index] )
		
		if res:
			print "! FOUND ", emuinfo.susp_string[index], "at", hex(res[0]['offset']) + ": " + res[0]['data']
		else:
			print "! NOT FOUND ", emuinfo.susp_string[index]

	for index in xrange(len(emuinfo.susp_string)):
		b64 = base64.b64encode(emuinfo.susp_string[index])
		res = emuinfo.r2.cmdj('/j ' + b64)
		if res:
			print "! Base64 FOUND ", emuinfo.susp_string[index], "at", hex(res[0]['offset']) + ": " + res[0]['data']
		else:
			print "! Base64 NOT FOUND ", emuinfo.susp_string[index]
'''

def PathFind(emuinfo, args=None):
	paths = emuinfo.r2.cmdj('afbj')
	if not paths:
		emuinfo.r2.cmd('f 1 @ ' + emuinfo.r2.cmd('s'))
		emuinfo.r2.cmd('af 1')
	#line = r2.cmdj("pdbj")[0]['offset']
	#print eapi.voy.bbs[0]['addr']
	#print "BBS Before"
	#print eapi.voy.bbs
	emuinfo.voy.__init__(emuinfo.r2) # Need to do this to reinit voy.bbs
	#print "BBS After"
	#print eapi.voy.bbs
	emuinfo.voy.PathFinder([], emuinfo.voy.bbs[0]['addr'])
	print 
	return
	

def PrintLoops(emuinfo, args=None):
	emuinfo.voy.ViewLoops()
	return	

def Verbosity(emuinfo, args=None):
	if not args:
		print 'Verbosity Level: ' + str(emuinfo.verbosity)
		return
	if args[0] == '+':
		emuinfo.verbosity += 1
		if emuinfo.verbosity > 2:
			emuinfo.verbosity = 2
	if args[0] == '++':
		emuinfo.verbosity = 2
	if args[0] == '-':
		emuinfo.verbosity -= 1
		if emuinfo.verbosity < 0:
			emuinfo.verbosity = 0
	if args[0] == '--':
		emuinfo.verbosity = 0

def RemoveBreakpoints(emuinfo, args=None):
	sketchy_functions    = [
		'sub.KERNEL32.dll_GetSystemTimeAsFileTime_b8c',
		'sub.KERNEL32.dll_SetUnhandledExceptionFilter_38c',
	]
	sketchy_instructions = [
		'int 3',
	]

	for sf in sketchy_functions:
		line = emuinfo.r2.cmdj("axtj " + sf)	
		if line:
			for element in line:
				nopslide = '0x'
				print "Break point found @ " + hex(element['fcn_addr'])
				instr = emuinfo.r2.cmdj('pdj 1 @' + hex(element['fcn_addr']))	
				length = len(instr[0]['bytes'])
				for index in xrange(length/2):
					nopslide += '90'
				emuinfo.r2.cmd("wx " + nopslide + " @ " + hex(element['fcn_addr']))
				print "Removed."
		else:
			print "No function breakpoints found."

	for si in sketchy_instructions:
		line = emuinfo.r2.cmdj("/cj " + si)	
		if line:	
			for element in line:
				nopslide = '0x'
				print "Break point found @ " + hex(element['offset'])
				instr = emuinfo.r2.cmdj('pdj 1 @' + hex(element['offset']))	
				length = len(instr[0]['bytes'])
				for index in xrange(length/2):
					nopslide += '90'
				emuinfo.r2.cmd("wx " + nopslide + " @ " + hex(element['offset']))
				print "Removed."
		else:
			print "No Breakpoints found."
	return

def Help(emuinfo=None, args=None):
	HELP = """COMMANDS:
	init [aebr]  - Initializes ESIL VM
	               a = analyze, e = emulation, b = symbols (separate with spaces), r = reset emuinfo variables
	symb         - Builds list of imports links known ones to our emulated API's
	loadmod      - Builds mock TIB/PEB and loads kernel32.dll export info 
	api          - Get a list of Suspicious APIs in the malware
	pathfind     - Examines a function and maps out all possible paths
	loops        - Examines a function and prints out possible loops
	v [+-]       - Changes verbosity levels using v + or v - to increase or decrease
	               Use v ++ for max verbosity or v -- for minimum verbosity
	x [cmd]      - Executes a python command
	string [x]   - Searches malware for suspicious looking strings
	               x = specific string to search (see emuinfo for default strings)
	cont [x]     - Continue Emulation
	               x = number of times to continue (default=1)
	ctf [x]      - Continue 'Til Fail, continues and automatically skips loops and takes expected returns
		           x = number of times to continue (default=infinity) 
	step [x]     - Analyzed Step
	               x = number of times to step (default=1)
	rmBreak      - Remove breakpoints set by malware author
	stop         - Exit and kill r2
	help         - Display this help"""
	print HELP

COMMANDS = {
	'init'    : InitEmu,
	'symb'    : BuildSymbols,
	'loadmod' : BuildInMemoryModules,
	'api'     : Api,
	'string'  : String,
	'cont'    : Continue,
	'ctf'	  : ContinueTilFail,
	'step'    : Step,
	'stop'    : Stop,
	'q'       : Stop,
	'quit'    : Stop,
	'pathfind': PathFind,
	'loops'   : PrintLoops,
	'v'       : Verbosity,
	'rmBreak' : RemoveBreakpoints,
	'help'    : Help,
}

#   MAIN
###################################################################################
def main(argv):
	r2   = r2pipe.open(argv[0])

	# check if executable that was loaded

	if not r2:
		Help()
		return

	emuinfo = EmuInfo(r2)

	print r2.cmd('?E Bruh')
	print "Enter help for a list of commands."

	while True:
		command = raw_input('[' + r2.cmd('s') + ']> ')
		
		if not command:
			continue

		scommand = command.split()

		if scommand[0] in COMMANDS:
			COMMANDS[scommand[0]](emuinfo, scommand[1:])
		elif scommand[0] == 'x':
			try:
				exec(command[2:])
			except Exception as e:
				print e
				pass
		else:
			print r2.cmd(command)


	
if __name__ == '__main__':
	if not sys.argv[1:]:
		print "! USAGE: python diamondfountain.py [inputfile]"
	else:
		main(sys.argv[1:])
