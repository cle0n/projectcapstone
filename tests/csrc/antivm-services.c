/*
	AntiVM: Services

	i686-w64-mingw32-gcc -municode -Wall -nostartfiles antivm-services.c -lshlwapi

*/

#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>



#define SIZEOFARR(x) \
	sizeof(x) / sizeof(x[0])
	
WCHAR	*szaServices[] = 
{
	L"VMTools",
	L"Vmhgfs",
	L"VMMEMCTL",
	L"Vmmouse",
	L"Vmrawdsk",
	L"Vmusbmouse",
	L"Vmvss",
	L"Vmscsi",
	L"Vmxnet",
	L"vmx_svga",
	L"Vmware Tools",
	L"Vmware Physical Disk Helper Service",
};

BOOL FindVMServices();
VOID DoEvil();

void wmain(int argc, WCHAR *argv[])
{
	if (FindVMServices())
		wprintf(L"[*] VMware Environment Detected!\n");
	else
		DoEvil();

	ExitProcess(0);
}

BOOL FindVMServices()
{
	DWORD 	cbBytesNeeded,
			ServicesReturned,
			ResumeHandle = 0,
			dwCount = 0;
			
	SC_HANDLE hSCManager;
	ENUM_SERVICE_STATUS ess [256] = { };
	
	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
	if (hSCManager != NULL)
	{
		if (!EnumServicesStatus(
				hSCManager,
				SERVICE_WIN32, 
				SERVICE_ACTIVE, 
				ess,
				sizeof(ess), 
				&cbBytesNeeded,
				&ServicesReturned, 
				&ResumeHandle))
		{
			wprintf(L"[-] ess size: %d\n", sizeof(ess));
			wprintf(L"[-] ERROR %d: Need %d\n", GetLastError(), cbBytesNeeded);
		}
		else
		{
			unsigned i, j;
			for (i = 0; i < ServicesReturned; i++)
				for(j = 0; j < SIZEOFARR(szaServices); j++)
					if (StrCmpNI(ess[i].lpServiceName, szaServices[j], wcslen(szaServices[j]) * sizeof(WCHAR)) == 0)
					{
						wprintf(L"[+] FOUND: %s\n", ess[i].lpDisplayName);
						dwCount++;
					}
		}
	}
	
	CloseServiceHandle(hSCManager);
	
	return dwCount ? TRUE : FALSE;
}

VOID DoEvil()
{
	wprintf(L"Shoulda-Woulda-Coulda.\n");
}