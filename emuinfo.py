#	EMUINFO
#
#
###################################################################################
from ihooks   import InsnHooks
from apihooks import ApiHooks

class EmuInfo(InsnHooks, ApiHooks):
	susp_reg_key = [
		'SOFTWARE\VMware, Inc.\VMware Tools',
		'HKEY_LOCAL_MACHINE\HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0\Identifier',
		'SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_VMware_&Prod_VMware_Virtual_S',
		'SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\\root#vmwvmcihostdev',
		'SYSTEM\CurrentControlSet\Control\VirtualDeviceDrivers',
	]
	
	susp_string = [
		"http", "00:05:69",
		"00:0C:29", "00:1C:14", 
		"00:50:56", "08:00:27", 
		"Vmtoolsd", "Vmwaretrat", "VMTools",
		"Vmhgfs", "VMMEMCTL", "Vmmouse", "Vmrawdsk",
		"Vmusbmouse", "Vmvss", "Vmscsi", "Vmxnet",
		"vmx_svga", "Vmware Tools", "Vmware Physical Disk Helper Service",
		"Vmwareuser","Vmacthlp", "vboxservice"
		"vboxtray","vm3dgl.dll","vmdum.dll","vm3dver.dll",
		"Vmmouse.sys", "vmtray.dll", "VMToolsHook.dll", "vmmousever.dll",
		"vmhgfs.dll", "vmGuestLib.dll", "VmGuestLibJava.dll", "Driversvmhgfs.dll",
		"VBoxMouse.sys", "VBoxGuest.sys", "VBoxSF.sys", "VBoxVideo.sys",
		"vboxdisp.dll", "vboxhook.dll", "vboxmrxnp.dll", "vboxogl.dll",
		"vboxoglarrayspu.dll", "vboxoglcrutil.dll", "vboxoglerrorspu.dll",
		"vboxoglfeedbackspu.dll", "vboxoglpackspu.dll", "vboxoglpassthroughspu.dll",
		"VBoxControl.exe", "vboxservice.exe", "vboxtray", "VMwareVMware", "VMware",
		"Microsoft HV",
	]

	susp_api = [
		'ShellExecuteA', 'ShellExecuteW',
		'AdjustTokenPriveleges',
		'CheckRemoteDebuggerPresent',
		'OleGetClipboard',
		'GetCommandLineA', 'GetCommandLineW',
		'TlsGetValue',
		'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
		'RegOpenKeyExA', 'RegOpenKeyExW',
		'VirtualAlloc', 'VirtualAllocEx',
		'VirtualProtect', 'VirtualProtectEx',
		'GetAdaptersAddresses',
		'GetProcAddress', 'LoadLibraryA', 'LoadLibraryW'
		'GetProcessHeap',
		'EnumServiceStatusW', 'OpenSCManagerW',
		'SetUnhandledExceptionFilter',
		'DbgUIConnectToDbg',
		'QueryInformationProcess',
		'OutputDebugString',
		'EventPairHandles',
		'CsrGetProcessID',
		'FindProcess',
		'FindWindow',
		'NtQueryObject',
		'NtQuerySysteminformation',
		'NtContinue',
		'NtClose',
		'GenerateConsoleCtrlEvent',
		'GetLocalTime',
		'GetSystemTime',
		'NtQueryPerformanceCounter',
	]
	
	def __init__(self, r2):
		InsnHooks.__init__(self)
		ApiHooks.__init__(self)

		self.r2        = r2

		self.verbosity = 0
		self.voy       = None
		self.ctf       = False
		self.CONTEXT   = {}
		self.ret_stk   = []
		self.jmp_stk   = {
			'count': {},
			'order': [],
		}

		self.loop_detected = False
		self.pushes = 0

