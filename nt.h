#pragma once
#include "windows.h"

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_SUCCESS                          ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH             ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_OVERFLOW                  ((NTSTATUS)0x80000005L)


#define SystemHandleInformation         16
#define ObjectBasicInformation          0
#define ObjectNameInformation           1
#define ObjectTypeInformation           2
#define HANDLE_TYPE_TOKEN	            0x5

#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
typedef time_t TIME;

/////////////////////////////////////////////////////////////////////////////
// CONFIG
typedef struct _VersionSpecificConfig
{
    // preset for Win732Bit
    DWORD						dwOffsetToPvScan0;
    DWORD						dwUniqueProcessIdOffset;
    DWORD						dwTokenOffset;
    DWORD						dwActiveProcessLinks;
    DWORD                       GdiSharedHandleTableOffset;
} VersionSpecificConfig;
/////////////////////////////////////////////////////////////////////////////
// new GDI code
typedef struct _SERVERINFO {
    DWORD						dwSRVIFlags;
    DWORD						cHandleEntries;
    WORD						wSRVIFlags;
    WORD						wRIPPID;
    WORD						wRIPError;
} SERVERINFO, *PSERVERINFO;

typedef struct _WNDMSG {
    DWORD						macMsgs;
    PBYTE						abMsgs;
} WNDMSG, *PWNDMSG;

typedef struct _USER_HANDLE_ENTRY
{
    void						*pKernel;
    union
    {
        PVOID					pi;
        PVOID					pti;
        PVOID					ppi;
    };
    BYTE						type;
    BYTE						flags;
    WORD						generation;
} USER_HANDLE_ENTRY, *PUSER_HANDLE_ENTRY;

typedef struct _SHAREDINFO {
    PSERVERINFO					psi;
    PUSER_HANDLE_ENTRY			aheList;
    ULONG						HeEntrySize;
    ULONG_PTR					pDispInfo;
    ULONG_PTR					ulSharedDelts;
    ULONG_PTR					awmControl;
    ULONG_PTR					DefWindowMsgs;
    ULONG_PTR					DefWindowSpecMsgs;
} SHAREDINFO, *PSHAREDINFO;
// 2 versions of GDICELL 
typedef struct _GDICELL32
{
    ULONG		pKernelAddress;
    USHORT		wProcessId;
    USHORT		wCount;
    USHORT		wUpper;
    USHORT		wType;
    ULONG		pUserAddress;
} GDICELL32, *PGDICELL32;

typedef struct _GDICELL64
{
    PVOID64		pKernelAddress;
    USHORT		wProcessId;
    USHORT		wCount;
    USHORT		wUpper;
    USHORT		wType;
    PVOID64		pUserAddress;
} GDICELL64, *PGDICELL64;
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
// Strings
typedef struct _STRING {
    WORD						Length;
    WORD						MaximumLength;
    CHAR						*Buffer;
} STRING, *PSTRING;

typedef struct _LSA_UNICODE_STRING {
    USHORT						Length;
    USHORT						MaximumLength;
    PWSTR						Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CURDIR {
    UNICODE_STRING 				DosPath;
    PVOID          				Handle;
} CURDIR, *PCURDIR;
//////////////////////////////////////////////////////////////////////////////
// Handels, Objects, system, process
typedef struct _PROCESS_ACCESS_TOKEN {
    HANDLE						Token;
    HANDLE						Thread;
} PROCESS_ACCESS_TOKEN, *PPROCESS_ACCESS_TOKEN;

typedef struct _CLIENT_ID {
    PVOID						UniqueProcess;
    PVOID						UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef VOID *POBJECT;
typedef struct _SYSTEM_HANDLE
{
    ULONG						ProcessId;
    BYTE						ObjectTypeNumber;
    BYTE						Flags;
    USHORT						Handle;
    PVOID						Object;
    ACCESS_MASK					GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG						Length;
    HANDLE						RootDirectory;
    PUNICODE_STRING				ObjectName;
    ULONG						Attributes;
    PVOID						SecurityDescriptor;
    PVOID						SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
    HANDLE						Section;
    PVOID						MappedBase;
    PVOID						ImageBase;
    ULONG						ImageSize;
    ULONG						Flags;
    USHORT						LoadOrderIndex;
    USHORT						InitOrderIndex;
    USHORT						LoadCount;
    USHORT						OffsetToFileName;
    UCHAR						FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG						Count;
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG						HandleCount;
    SYSTEM_HANDLE				Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION
{
    LONG						ExitStatus;
    PVOID						PebBaseAddress;
    ULONG_PTR					AffinityMask;
    LONG						BasePriority;
    ULONG_PTR					UniqueProcessId;
    ULONG_PTR					ParentProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11,
    SystemHandleInformations = 16 // added s on end otherwise conflicts with the defines...
} SYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessTlsInformation,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    ProcessGroupInformation,
    ProcessTokenVirtualizationEnabled,
    ProcessConsoleHostProcess,
    ProcessWindowInformation,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef struct _EPROCESS {
    UCHAR NotNeeded1[0x26C];
    union {
        ULONG Flags2;
        struct {
            ULONG JobNotReallyActive : 1;
            ULONG AccountingFolded : 1;
            ULONG NewProcessReported : 1;
            ULONG ExitProcessReported : 1;
            ULONG ReportCommitChanges : 1;
            ULONG LastReportMemory : 1;
            ULONG ReportPhysicalPageChanges : 1;
            ULONG HandleTableRundown : 1;
            ULONG NeedsHandleRundown : 1;
            ULONG RefTraceEnabled : 1;
            ULONG NumaAware : 1;
            ULONG ProtectedProcess : 1;
            ULONG DefaultPagePriority : 3;
            ULONG PrimaryTokenFrozen : 1;
            ULONG ProcessVerifierTarget : 1;
            ULONG StackRandomizationDisabled : 1;
            ULONG AffinityPermanent : 1;
            ULONG AffinityUpdateEnable : 1;
            ULONG PropagateNode : 1;
            ULONG ExplicitAffinity : 1;
        };
    };
    UCHAR NotNeeded2[0x50];
} EPROCESS, *PEPROCESS;
/////////////////////////////////////////////
// RTL
typedef NTSTATUS(NTAPI *_RtlEnterCriticalSection)(PRTL_CRITICAL_SECTION CriticalSection);

typedef NTSTATUS(NTAPI *_RtlLeaveCriticalSection)(PRTL_CRITICAL_SECTION CriticalSection);

typedef void (WINAPI* _RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    WORD						Flags;
    WORD						Length;
    ULONG						TimeStamp; // orly...?
    STRING						DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;
//
typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG          				MaxLength;
    ULONG          				Length;
    ULONG          				Flags;
    ULONG          				DebugFlags;
    PVOID          				ConsoleHandle;
    ULONG          				ConsoleFlags;
    PVOID          				StandardIn;
    PVOID          				StandardOut;
    PVOID          				StandardErr;
    CURDIR         				CurrentDirectory;
    UNICODE_STRING 				DllPath;
    UNICODE_STRING 				ImagePathName;
    UNICODE_STRING 				CommandLine;
    PVOID          				Env;
    ULONG          				StartingX;
    ULONG         				StartingY;
    ULONG          				CountX;
    ULONG          				CountY;
    ULONG          				CountCharsX;
    ULONG          				CountCharsY;
    ULONG          				FillAttribute;
    ULONG						WindowFlags;
    ULONG						ShowWindowFlags;
    UNICODE_STRING				WindowTitle;
    UNICODE_STRING				DesktopInfo;
    UNICODE_STRING				ShellInfo;
    UNICODE_STRING				RuntimeData;
    RTL_DRIVE_LETTER_CURDIR		CurrentDirectores[32];
    UINT64						EnvSize;
    UINT64						EnvVersion;
    // etc.. etc.. lazy...
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
//
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY					InLoadOrderLinks;
    LIST_ENTRY					InMemoryOrderLinks;
    union
    {
        LIST_ENTRY				InInitializationOrderLinks;
        LIST_ENTRY				InProgressLinks;
    };
    PVOID						DllBase;
    PVOID						EntryPoint;
    ULONG						SizeOfImage;
    UNICODE_STRING				FullDllName;
    UNICODE_STRING				BaseDllName;
    ULONG						Flags;
    WORD						LoadCount;
    WORD						TlsIndex;
    union
    {
        LIST_ENTRY				HashLinks;
        struct
        {
            PVOID				SectionPointer;
            ULONG				CheckSum;
        };
    };
    union
    {
        ULONG					TimeDateStamp;
        PVOID					LoadedImports;
    };
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
//////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////
// NT imports from HEVD
typedef NTSTATUS(WINAPI *ZwClose_t)(IN HANDLE hObject);

typedef PEPROCESS(WINAPI *PsGetCurrentProcess_t)(VOID);

typedef NTSTATUS(WINAPI *NtQueryIntervalProfile_t)(
    IN ULONG					ProfileSource,
    OUT PULONG					Interval);

typedef NTSTATUS(WINAPI *ZwOpenProcessToken_t)(
    IN HANDLE					ProcessHandle,
    IN ACCESS_MASK				DesiredAccess,
    OUT PHANDLE					TokenHandle);

typedef NTSTATUS(WINAPI *ZwSetInformationProcess_t)(
    IN HANDLE					hProcess,
    IN ULONG					ProcessInfoClass,
    IN PVOID					ProcessInfo,
    IN ULONG					ProcessInfoLength);

typedef NTSTATUS(WINAPI *ZwOpenProcess_t)(
    OUT PHANDLE					ProcessHandle,
    IN ACCESS_MASK				DesiredAccess,
    IN POBJECT_ATTRIBUTES		ObjectAttributes,
    IN PCLIENT_ID				ClientId OPTIONAL);

typedef NTSTATUS(WINAPI *NtAllocateVirtualMemory_t)(
    IN HANDLE					ProcessHandle,
    IN OUT PVOID				*BaseAddress,
    IN ULONG					ZeroBits,
    IN OUT PULONG				AllocationSize,
    IN ULONG					AllocationType,
    IN ULONG					Protect);

typedef NTSTATUS(WINAPI *NtAllocateReserveObject_t)(
    OUT PHANDLE					hObject,
    IN POBJECT_ATTRIBUTES		ObjectAttributes,
    IN DWORD					ObjectType);

typedef NTSTATUS(WINAPI *NtMapUserPhysicalPages_t)(
    IN PVOID					VirtualAddress,
    IN ULONG_PTR				NumberOfPages,
    IN OUT PULONG_PTR			UserPfnArray);

typedef NTSTATUS(WINAPI	*ZwDuplicateToken_t)(
    IN HANDLE					ExistingTokenHandle,
    IN ACCESS_MASK				DesiredAccess,
    IN POBJECT_ATTRIBUTES		ObjectAttributes,
    IN BOOLEAN					EffectiveOnly,
    IN TOKEN_TYPE				TokenType,
    OUT PHANDLE					NewTokenHandle);

typedef NTSTATUS(WINAPI *NtQuerySystemInformation_t)(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID                   SystemInformation,
    IN ULONG                    SystemInformationLength,
    OUT PULONG                  ReturnLength);
////////////////////////////////////////////////////////
// Real NT imports
typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
    ULONG						SystemInformationClass,
    PVOID						SystemInformation,
    ULONG						SystemInformationLength,
    PULONG						ReturnLength);

typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
    HANDLE						SourceProcessHandle,
    HANDLE						SourceHandle,
    HANDLE						TargetProcessHandle,
    PHANDLE						TargetHandle,
    ACCESS_MASK					DesiredAccess,
    ULONG						Attributes,
    ULONG						Options);

typedef NTSTATUS(NTAPI *_NtQueryObject)(
    HANDLE						ObjectHandle,
    ULONG						ObjectInformationClass,
    PVOID						ObjectInformation,
    ULONG						ObjectInformationLength,
    PULONG						ReturnLength);

typedef NTSTATUS(NTAPI *_NtQueryIntervalProfile)(
    ULONG						ProfileSource,
    PULONG						Interval);

typedef NTSTATUS(NTAPI *_RtlGetVersion)(
    LPOSVERSIONINFOEXW			lpVersionInformation);

typedef NTSTATUS(NTAPI *_NtQueryInformationProcess)(
    HANDLE						ProcessHandle,
    DWORD						ProcessInformationClass,
    PVOID						ProcessInformation,
    DWORD						ProcessInformationLength,
    PDWORD						ReturnLength);
///////////////////////////////////////////////////////////
// PEB and GDI stuff
typedef struct _GDICELL {
    LPVOID pKernelAddress;
    USHORT wProcessId;
    USHORT wCount;
    USHORT wUpper;
    USHORT wType;
    LPVOID pUserAddress;
} GDICELL, *PGDICELL;

typedef struct _PEB_LDR_DATA {
    ULONG						Length;
    BOOLEAN						Initialized;
    HANDLE						SsHandle;
    LIST_ENTRY					InLoadOrderModuleList;
    LIST_ENTRY					InMemoryOrderModuleList;
    LIST_ENTRY					InInitializationOrderModuleList;
    PVOID						EntryInProgress;
    BOOLEAN						ShutdownInProgress;
    HANDLE						ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// Partial PEB
typedef struct _PEB {
    BOOLEAN						InheritedAddressSpace;
    BOOLEAN						ReadImageFileExecOptions;
    BOOLEAN						BeingDebugged;
    union
    {
        BOOLEAN					BitField;
        struct
        {
            BOOLEAN				ImageUsesLargePages : 1;
            BOOLEAN				IsProtectedProcess : 1;
            BOOLEAN				IsLegacyProcess : 1;
            BOOLEAN				IsImageDynamicallyRelocated : 1;
            BOOLEAN				SkipPatchingUser32Forwarders : 1;
            BOOLEAN				SpareBits : 3;
        };
    };
    HANDLE						Mutant;
    PVOID						ImageBaseAddress;
    PPEB_LDR_DATA				Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters; // modified (2hours wasted forgot the P)
    PVOID						SubSystemData;
    PVOID						ProcessHeap;
    PRTL_CRITICAL_SECTION		FastPebLock;
    PVOID						AtlThunkSListPtr;
    PVOID						IFEOKey;
    union
    {
        ULONG					CrossProcessFlags;
        struct
        {
            ULONG				ProcessInJob : 1;
            ULONG				ProcessInitializing : 1;
            ULONG				ProcessUsingVEH : 1;
            ULONG				ProcessUsingVCH : 1;
            ULONG				ProcessUsingFTH : 1;
            ULONG				ReservedBits0 : 27;
        };
        ULONG					EnvironmentUpdateCount;
    };
    union
    {
        PVOID					KernelCallbackTable;
        PVOID					UserSharedInfoPtr;
    };
    ULONG						SystemReserved[1];
    ULONG 						AtlThunkSListPtr32;
    PVOID 						ApiSetMap;
    ULONG 						TlsExpansionCounter;
    PVOID 						TlsBitmap;
    ULONG 						TlsBitmapBits[2];
    PVOID 						ReadOnlySharedMemoryBase;
    PVOID 						HotpatchInformation;
    PVOID 						*ReadOnlyStaticServerData;
    PVOID 						AnsiCodePageData;
    PVOID 						OemCodePageData;
    PVOID 						UnicodeCaseTableData;
    ULONG 						NumberOfProcessors; // if > 1 == "scan box" nuke it ;)
    ULONG 						NtGlobalFlag;
    LARGE_INTEGER				CriticalSectionTimeout;
    SIZE_T						HeapSegmentReserve;
    SIZE_T						HeapSegmentCommit;
    SIZE_T						HeapDeCommitTotalFreeThreshold;
    SIZE_T						HeapDeCommitFreeBlockThreshold;
    ULONG 						NumberOfHeaps;
    ULONG 						MaximumNumberOfHeaps;
    PVOID 						*ProcessHeaps;
    PVOID 						GdiSharedHandleTable;
} PEB, *PPEB;


typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING				Name;
    ULONG           			TotalNumberOfObjects;
    ULONG           			TotalNumberOfHandles;
    ULONG           			TotalPagedPoolUsage;
    ULONG           			TotalNonPagedPoolUsage;
    ULONG           			TotalNamePoolUsage;
    ULONG           			TotalHandleTableUsage;
    ULONG           			HighWaterNumberOfObjects;
    ULONG           			HighWaterNumberOfHandles;
    ULONG           			HighWaterPagedPoolUsage;
    ULONG           			HighWaterNonPagedPoolUsage;
    ULONG           			HighWaterNamePoolUsage;
    ULONG           			HighWaterHandleTableUsage;
    ULONG           			InvalidAttributes;
    GENERIC_MAPPING 			GenericMapping;
    ULONG           			ValidAccess;
    BOOLEAN         			SecurityRequired;
    BOOLEAN         			MaintainHandleCount;
    USHORT          			MaintainTypeList;
    POOL_TYPE       			PoolType;
    ULONG           			PagedPoolUsage;
    ULONG           			NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;
/////////////////////////////////////////////////////////
