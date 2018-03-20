/*
	AntiVM: Files
	
	i686-w64-mingw32-gcc -municode -nostartfiles -Wall antivm-files.c
	
*/

#include <windows.h>
#include <stdio.h>



#define SIZEOFARR(x) \
	sizeof(x) / sizeof(x[0])
	
WCHAR	*szaFiles[] = {
	L"%windir%\\Sysnative\\Drivers\\vmmouse.sys",
	L"%windir%\\System32\\vm3dgl.dll",
	L"%windir%\\Sysnative\\Drivers\\vmdum.dll",
	L"C:\\Program Files\\Common Files\\VMware\\Drivers\\video_wddm\\vm3dver.dll",
	L"C:\\Program Files\\VMware\\VMware Tools\\plugins\\vmusr\\vmtray.dll",
	L"C:\\Program Files\\VMware\\VMware Tools\\VMToolsHook.dll",
	L"C:\\Program Files\\Common Files\\VMware\\Drivers\\mouse\\vmmousever.dll",
	L"%windir%\\Sysnative\\vmhgfs.dll",
	L"%windir%\\Sysnative\\vmGuestLib.dll",
	L"%windir%\\Sysnative\\VmGuestLibJava.dll",
};

static BOOL FindVM();
static VOID DoEvil();

// if compiling with -nostartfiles then:
// Function prototypes are necessary and MAIN should be at the top 
void wmain(int argc, WCHAR *argv[])
{
	if (FindVM())
		wprintf(L"[-] VMware Environment Detected!\n");
	else
		DoEvil();
	
	ExitProcess(0);
}
	
BOOL FindVM()
{
	HANDLE           hFind;
	WIN32_FIND_DATA  ffd;
	WCHAR            szPath[MAX_PATH] = { };
	DWORD            dwCount = 0;
	
	unsigned i = 0;
	for (; i < SIZEOFARR(szaFiles); i++)
	{
		ExpandEnvironmentStrings(szaFiles[i], szPath, MAX_PATH);
		
		hFind = FindFirstFile(szPath, &ffd);
		if (hFind == INVALID_HANDLE_VALUE)
			wprintf(L"[-] ERROR: %d, NOT FOUND: %s\n", GetLastError(), szPath);
		else
		{
			wprintf(L"[!] FOUND: %s\n", szPath);
			FindClose(hFind);
			dwCount++;
		}
		ZeroMemory(szPath, MAX_PATH);
	}
	
	return dwCount ? TRUE : FALSE;
}

VOID DoEvil()
{
	wprintf(L"2 + 2 = 5\n");
}