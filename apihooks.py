#	API HOOK CALLBACKS
#
#
###################################################################################
class ApiHooks:
	def __init__(self):
		self.SYMBOLS     = { }
		self.SYMBOLHOOKS = {
			'diamond_def'               : self._DiamondDefault,
			'RegOpenKeyExW'             : self._RegOpenKeyExW,
			'RegCloseKey'               : self._RegCloseKey,
			'ExitProcess'               : self._ExitProcess,
			'GetAdaptersAddresses'      : self._GetAdaptersAddresses,
			'GetProcessHeap'            : self._GetProcessHeap,
			'HeapAlloc'                 : self._HeapAlloc,
			'HeapFree'                  : self._HeapFree,
			'StrCmpNI'                  : self._StrCmpNI,
			'StrRStrIW'                 : self._StrRStrIW,
			'ExpandEnvironmentStringsW' : self._ExpandEnvironmentStrings,
			'FindFirstFileW'            : self._FindFirstFileW,
			'FindClose'                 : self._FindClose,
			'EnumProcesses'             : self._EnumProcesses,
			'OpenProcess'               : self._OpenProcess,
			'CloseHandle'               : self._CloseHandle,
			'GetModuleFileNameExW'      : self._GetModuleFileNameExW,
			'OpenSCManagerW'            : self._OpenSCManagerW,
			'EnumServiceStatusW'        : self._EnumServiceStatusW,
			'CloseServiceHandle'        : self._CloseServiceHandle,
			'GetLastError'              : self._GetLastError,
			'wprintf'                   : self._wprintf,
			'_snwprintf'                : self.__snwprintf,
			'memset'                    : self._memset,
			'wcslen'                    : self._wcslen,
			'GetSystemTimeAsFileTime'   : self._GetSystemTimeAsFileTime,
			'GetCurrentProcessId'       : self._GetCurrentProcessId,
			'GetCurrentThreadId'        : self._GetCurrentThreadId,
			'GetTickCount'              : self._GetTickCount,
			'QueryPerformanceCounter'   : self._QueryPerformanceCounter,
			'LoadLibraryA'              : self._LoadLibraryA,
			'GetProcAddress'            : self._GetProcAddress,
			'SetErrorMode'              : self._SetErrorMode,
			'GetModuleFileNameA'        : self._GetModuleFileNameA,
			'GetCurrentDirectoryA'      : self._GetCurrentDirectoryA,
			'GetComputerNameA'          : self._GetComputerNameA,
			'GetFileAttributesA'        : self._GetFileAttributesA,
			'TlsGetValue'               : self._TlsGetValue,
			'GlobalUnfix'               : self._GlobalUnfix,
			'IsDebuggerPresent'         : self._IsDebuggerPresent,
			'CheckRemoteDebuggerPresent': self._CheckRemoteDebuggerPresent,
			#'SetUnhandledExceptionFilter': self._SetUnhandledExceptionFilter,
			#'DbgUIConnectToDbg'		    : self._DbgUIConnectToDbg,
			#'QueryInformationProcess'	: self._QueryInformationProcess,
			#'OutputDebugString'		    : self._OutputDebugString,
			#'EventPairHandles'		    : self._EventPairHandles,
			#'CsrGetProcessID'		    : self._CsrGetProcessID,
			#'FindProcess'			    : self._FindProcess,
			#'FindWindow'			    : self._FindWindow,
			#'NtQueryObject'			    : self._NtQueryObject,
			#'NtQuerySysteminformation'	: self._NtQuerySysteminformation,
			#'NtContinue'			    : self._NtContinue,
			#'NtClose'			        : self._NtClose,
			#'GenerateConsoleCtrlEvent'	: self._GenerateConsoleCtrlEvent,
			#'GetLocalTime'			    : self._GetLocalTime,
			#'GetSystemTime'			    : self._GetSystemTime,
			#'NtQueryPerformanceCounter'	: self._NtQueryPerformanceCounter,
		}

	def _DiamondDefault(self, emuinfo):
		if emuinfo.verbosity > 0:
			print "! Unknown API"
			print emuinfo.r2.cmd('pd 1')
		return

	def _IsDebuggerPresent(self, emuinfo):
		print "! IsDebuggerPresent"
		answer = raw_input("Would you like to remove this API call? (y or n)")
		type(answer)
		
		while True:
			if answer in ['y', 'Y', 'yes', 'Yes', 'YES']:
				print("Getting rid of IsDebuggerPresent.")
				emuinfo.r2.cmd('wa \"mov eax, 0\" ')
			
			elif answer in ['n', 'N', 'no', 'No', 'NO']:		
				break;
			else:
				print "Invalid answer."

	def _CheckRemoteDebuggerPresent(self, emuinfo):
		#print "! LIKELY MALICIOUS CALL"
		print "! CheckRemoteDebuggerPresent"
		#print "! Address: " + emuinfo.r2.cmd('/o 1 @ `ar eip`')
		emuinfo.r2.cmd('ar esp=esp+8')
			
	def _GetAdaptersAddresses(self, emuinfo):
		print "! GetAdaptersAddresses #TODO"
	def _GetProcessHeap(self, emuinfo):
		print "! GetProcessHeap #TODO"
	def _HeapAlloc(self, emuinfo):
		print "! HeapAlloc #TODO"
	def _HeapFree(self, emuinfo):
		print "! HeapFree #TODO"
	def _StrCmpNI(self, emuinfo):
		print "! StrCmpNI #TODO"
	def _ExpandEnvironmentStrings(self, emuinfo):
		print "! ExpandEnvironmentStrings #TODO"
	def _FindFirstFileW(self, emuinfo):
		print "! FindFirstFileW #TODO"
	def _FindClose(self, emuinfo):
		print "! FindClose #TODO"
	def _OpenSCManagerW(self, emuinfo):
		print "! OpenSCManagerW #TODO"
	def _EnumServiceStatusW(self, emuinfo):
		print "! EnumServiceStatusW #TODO"
	def _CloseServiceHandle(self, emuinfo):
		print "! CloseServiceHandle #TODO"
	def _GetLastError(self, emuinfo):
		print "! GetLastError #TODO"
	def __snwprintf(self, emuinfo):
		print "! _snwprintf #TODO"
	def _memset(self, emuinfo):
		print "! memset #TODO"
	def _wcslen(self, emuinfo):
		print "! wcslen #TODO"

	def _GetFileAttributesA(self, emuinfo):
		print "! GetFileAttributesA"
		print "  > ARG: '" + emuinfo.r2.cmd('ps @ [esp]') + "'"
		emuinfo.r2.cmd('ar esp=esp+4')
		emuinfo.r2.cmd('ar eax=0x80') # return FILE_ATTRIBUTE_NORMAL by default

	def _GetComputerNameA(self, emuinfo):
		print "! GetComputerNameA"
		cname = r"DESKTOP-570DAJQ"
		print "  > Using dummy data: " + cname
		loc = emuinfo.r2.cmdj('pxwj 4 @ esp')
		emuinfo.r2.cmd('wz ' + cname + ' @ ' + hex(loc[0]))
		emuinfo.r2.cmd('ar esp=esp+8')
		emuinfo.r2.cmd('ar eax=1')

	def _GetCurrentDirectoryA(self, emuinfo):
		print "! GetCurrentDirectoryA"
		dummy = r"C:\\Users\\Dummy\\Desktop"
		print "  > Using dummy data: " + dummy
		loc   = emuinfo.r2.cmdj('pxwj 4 @ esp+4')
		emuinfo.r2.cmd('wz ' + dummy + ' @ ' + hex(loc[0]))
		emuinfo.r2.cmd('ar esp=esp+8')
		emuinfo.r2.cmd('ar eax=' + hex(len(dummy) - 4))

	def _GetModuleFileNameA(self, emuinfo):
		print "! GetModuleFileNameA"
		dummy = r"C:\\Users\\Dummy\\Desktop\\dumb.exe"
		print "  > Using dummy data: " + dummy
		loc   = emuinfo.r2.cmdj('pxwj 4 @ esp+4')
		emuinfo.r2.cmd('wz ' + dummy + ' @ ' + hex(loc[0]))
		emuinfo.r2.cmd('ar esp=esp+12')
		emuinfo.r2.cmd('ar eax=' + hex(len(dummy) - 5))

	def _SetErrorMode(self, emuinfo):
		print "! SetErrorMode"
		emuinfo.r2.cmd('ar esp=esp+4')
		emuinfo.r2.cmd('ar eax=1')

	def _GetProcAddress(self, emuinfo):
		print "! GetProcAddress"
		API = emuinfo.r2.cmd('ps @ [esp+4]')
		print "  > ARG: '" + API + "'"
		emuinfo.r2.cmd('ar esp=esp+8')

		# get rid of the try-catch
		for sym in self.SYMBOLS:
			try:
				if self.SYMBOLS[sym] == self.SYMBOLHOOKS[API]:
					emuinfo.r2.cmd('ar eax=' + hex(sym))
					break
			except KeyError:
				pass

	def _LoadLibraryA(self, emuinfo):
		print "! LoadLibraryA #TODO"
		print "  > ARG: '" + emuinfo.r2.cmd('ps @ [esp]') + "'"
		emuinfo.r2.cmd('ar esp=esp+4')
		emuinfo.r2.cmd('ar eax=0x77FD0000')
		
	def _RegOpenKeyExW(self, emuinfo):
		print "! RegOpenKeyExW"
		
		strarg = emuinfo.r2.cmd('psw @ [esp+4]')
		
		if strarg in emuinfo.susp_reg_key:
			print "! VMware registry key check"
		
		print "  > ARG: '" + strarg + "'"
		
		emuinfo.r2.cmd('ar eax=0')

	def _RegCloseKey(self, emuinfo):
		print "! RegCloseKey"
		emuinfo.r2.cmd('ar eax=0')
		return
		
	def _ExitProcess(self, emuinfo):
		print "! ExitProcess"
		return
		
	def _wprintf(self, emuinfo):
		print "! _wprintf #TODO"
		emuinfo.r2.cmd('ar eax=0')
		return
	def _GetSystemTimeAsFileTime(self, emuinfo):
		print "! GetSystemTimeAsFileTime"
		emuinfo.r2.cmd('ar esp=esp+4')

	def _GetCurrentProcessId(self, emuinfo):
		print "! GetCurrentProcessId"
		emuinfo.r2.cmd('ar eax=1')

	def _GetCurrentThreadId(self, emuinfo):
		print "! GetCurrentThreadId"
		emuinfo.r2.cmd('ar eax=1')

	def _GetTickCount(self, emuinfo):
		print "! GetTickCount"
		emuinfo.r2.cmd('ar eax=1')

	def _QueryPerformanceCounter(self, emuinfo):
		print "! QueryPerformanceCounter"
		emuinfo.r2.cmd('ar esp=esp+4')
		emuinfo.r2.cmd('ar eax=1')
		
	def _OpenProcess(self, emuinfo):
		print "! OpenProcess"
		emuinfo.r2.cmd('ar esp=esp+12')
		emuinfo.r2.cmd('ar eax=1111')

	def _CloseHandle(self, emuinfo):
		print "! CloseHandle"
		emuinfo.r2.cmd('ar esp=esp+4')
		emuinfo.r2.cmd('ar eax=1')

	def _GetModuleFileNameExW(self, emuinfo):
		print "! GetModuleFileNameExW"
		emuinfo.r2.cmd('ar esp=esp+12')
		emuinfo.r2.cmd('ar eax=1')

	def _StrRStrIW(self, emuinfo):
		print "! StrRStrIW"
		print "  > ARG: " + emuinfo.r2.cmd('psw @ [esp+8]')
		emuinfo.r2.cmd('ar esp=esp+12')
		emuinfo.r2.cmd('ar eax=1')

	def _EnumProcesses(self, emuinfo):
		print "! EnumProcesses"
		emuinfo.r2.cmd('wv 0x666 @ [esp]')
		emuinfo.r2.cmd('wv 0x4 @ [esp+8]')
		emuinfo.r2.cmd('ar esp=esp+12')
		emuinfo.r2.cmd('ar eax=1')

	def _TlsGetValue(self, emuinfo):
		print "! TlsGetValue"
		emuinfo.r2.cmd('ar esp=esp+4')
		emuinfo.r2.cmd('ar eax=1')

	def _GlobalUnfix(self, emuinfo):
		print "! GlobalUnfix"
		emuinfo.r2.cmd('ar esp=esp+4')
		emuinfo.r2.cmd('ar eax=1')


