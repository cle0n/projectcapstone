/*
	AntiVM: MAC / Network Adapter
	
	i686-w64-mingw32-gcc -municode -Wall -nostartfiles antivm-adapter.c -liphlpapi -lshlwapi
*/

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>



#define SIZEOFARR(x) \
	sizeof(x) / sizeof(x[0])
	
WCHAR	*szaMAC[] =
{
	L"00:05:69",
	L"00:0C:29",
	L"00:1C:14",
	L"00:50:56",
};
	
BOOL FindVMAdapter();
VOID DoEvil();

void wmain(int argc, WCHAR *argv[])
{
	if (FindVMAdapter())
		wprintf(L"[*] VMware Environment Detected!\n");
	else
		DoEvil();
	
	ExitProcess(0);
}

BOOL FindVMAdapter()
{
	WCHAR szMACOUI [18] = { };
	IP_ADAPTER_ADDRESSES *iaa, *piaa;
	DWORD cbSize;
	DWORD dwCount = 0;
	
	// Need GetAdaptersAddresses to fail first so it can populate cbSize with the size it requires.
	if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, NULL, &cbSize) != ERROR_BUFFER_OVERFLOW)
		return FALSE;
	
	// GetAdaptersAddresses creates a linked-list so we need to allocate space for it
	iaa = (IP_ADAPTER_ADDRESSES *) HeapAlloc(GetProcessHeap(), 0, cbSize);
	
	if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, iaa, &cbSize) == ERROR_SUCCESS)
	{
		piaa = iaa;
		while (piaa)
		{
			if (piaa->PhysicalAddressLength != 0)
			{
				_snwprintf(
					szMACOUI, 
					18, 
					L"%.2X:%.2X:%.2X", 
					piaa->PhysicalAddress[0], 
					piaa->PhysicalAddress[1], 
					piaa->PhysicalAddress[2]
				);
				
				unsigned i;
				for(i = 0; i < SIZEOFARR(szaMAC); i++)
					if (StrCmpNI(szMACOUI, szaMAC[i], 18) == 0)
					{
						wprintf(L"[+] FOUND: %s\n", szaMAC[i]);
						dwCount++;
					}
			}
			piaa = piaa->Next;
		}
	}

	HeapFree(GetProcessHeap(), 0, iaa);
	
	return dwCount ? TRUE : FALSE;
}

VOID DoEvil()
{
	wprintf(L"[+] Aliens.\n");
}
