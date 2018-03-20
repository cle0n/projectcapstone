/*
	AntiVM: Processes via PSAPI
	
	i686-w64-mingw32-gcc -municode -Wall -nostartfiles antivm-process.c -lpsapi -lshlwapi

*/

#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <stdio.h>



#define SIZEOFARR(x) \
	sizeof(x) / sizeof(x[0])
	
WCHAR	*szaProcess[] = 
{
	L"Vmtoolsd.exe",
	L"Vmwaretrat.exe",
	L"Vmwareuser.exe",
	L"Vmacthlp.exe",
};

BOOL FindVMProc();
VOID DoEvil();

void wmain(int argc, WCHAR *argv[])
{
	if (FindVMProc())
		wprintf(L"[!] VMware Environment Detected!\n");
	else
		DoEvil();
	
	ExitProcess(0);
}

BOOL FindVMProc()
{
	HANDLE	hProcess;
	WCHAR	szProcessName[MAX_PATH] = { };
	DWORD	aProcesses[1024],
			cbSize,
			dwCount = 0;
	
	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbSize))
		ExitProcess(1);
	
	cbSize = cbSize / sizeof(DWORD);
	
	//wprintf(L"[*] Number of processes: %d\n", cbSize);
	
	unsigned i = 0;
	for (; i < cbSize; i++)
	{
		if (aProcesses[i] != 0)
		{
			hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
			if (hProcess != NULL)
			{
				GetModuleFileNameEx(hProcess, NULL, szProcessName, MAX_PATH);
				
				unsigned j = 0;
				for (; j < SIZEOFARR(szaProcess); j++)
				{
					if (StrRStrIW(szProcessName, NULL, szaProcess[j]) != NULL)
					{
						wprintf(L"[+] FOUND: %s\n", szProcessName);
						dwCount++;
					}
				}
			}
			CloseHandle(hProcess);
		}
			
	}
	
	return dwCount ? TRUE : FALSE;
}

VOID DoEvil()
{
	wprintf(L"All your base are belong to us.\n");
}