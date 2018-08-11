/*
	AntiVM: Registry
	
	i686-w64-mingw32-gcc -municode -Wall -nostartfiles antivm-registry.c
*/

#include <windows.h>
#include <stdio.h>



#define SIZEOFARR(x) \
	sizeof(x) / sizeof(x[0])
	
WCHAR	*szaRegistry[] =
{
	L"SOFTWARE\\VMware, Inc.\\VMware Tools",
	L"SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_VMware_&Prod_VMware_Virtual_S",
};

BOOL FindVMRegistry();
VOID DoEvil();

void wmain(int argc, WCHAR *argv[])
{
	if (FindVMRegistry())
		wprintf(L"[*] VMware Environment Detected!\n");
	else
		DoEvil();
	
	ExitProcess(0);
}

BOOL FindVMRegistry()
{
	HKEY hKey;
	DWORD dwCount = 0;
	
	unsigned i;
	for (i = 0; i < SIZEOFARR(szaRegistry); i++)
	{
		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, szaRegistry[i], 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
		{	
			wprintf(L"[*] FOUND: %s\n", szaRegistry[i]);
			RegCloseKey(hKey);
			dwCount++;
		}
		//wprintf(L"[-] %d, %s\n", GetLastError(), szaRegistry[i]);
	}
	return dwCount ? TRUE : FALSE;
}

VOID DoEvil()
{
	wprintf(L"[*] Lah-who...za-her.\n");
}