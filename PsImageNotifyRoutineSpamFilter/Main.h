/*
	PsImageNotifyRoutine Spam Filter v1.0

	Copyright (c) 2016 Maarten Boone
	Permission is hereby granted, free of charge, to any person
	obtaining a copy of this software and associated documentation
	files (the "Software"), to deal in the Software without
	restriction, including without limitation the rights to use,
	copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the
	Software is furnished to do so, subject to the following
	conditions:
	The above copyright notice and this permission notice shall be
	included in all copies or substantial portions of the Software.
	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
	EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
	OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
	HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
	WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
	FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
	OTHER DEALINGS IN THE SOFTWARE.
*/

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

#define FramesToSkip		1
#define FramesToCapture		16
#define MAX_STACK_DEPTH		32

#define KERNEL_MODE_STACK	0
#define USER_MODE_STACK		1

#define LdrLoadDllSize		0x400

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32		InLoadOrderLinks;
	LIST_ENTRY32		InMemoryOrderLinks;
	LIST_ENTRY32		InInitializationOrderLinks;
	ULONG				DllBase;
	ULONG				EntryPoint;
	ULONG				SizeOfImage;
	UNICODE_STRING32	FullDllName;
	UNICODE_STRING32	BaseDllName;
	ULONG				Flags;
	USHORT				LoadCount;
	USHORT				TlsIndex;
	LIST_ENTRY32		HashLinks;
	ULONG				TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64		InLoadOrderLinks;
	LIST_ENTRY64		InMemoryOrderLinks;
	LIST_ENTRY64		InInitializationOrderLinks;
	VOID*				DllBase;
	VOID*				EntryPoint;
	ULONG				SizeOfImage;
	UCHAR				_PADDING0_[0x4];
	UNICODE_STRING64	FullDllName;
	UNICODE_STRING64	BaseDllName;
	ULONG				Flags;
	USHORT				LoadCount;
	USHORT				TlsIndex;
	LIST_ENTRY64		HashLinks;
	ULONG32				TimeDateStamp;
}LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

typedef struct _PEB_LDR_DATA32
{
	ULONG				Length;
	UCHAR				Initialized;
	UCHAR				_PADDING0_[0x3];
	ULONG				SsHandle;
	LIST_ENTRY32		InLoadOrderModuleList;
	LIST_ENTRY32		InMemoryOrderModuleList;
	LIST_ENTRY32		InInitializationOrderModuleList;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _PEB_LDR_DATA64
{
	ULONG				Length;
	UCHAR				Initialized;
	UCHAR				_PADDING0_[0x3];
	VOID*				SsHandle;
	LIST_ENTRY64		InLoadOrderModuleList;
	LIST_ENTRY64		InMemoryOrderModuleList;
	LIST_ENTRY64		InInitializationOrderModuleList;
}PEB_LDR_DATA64, *PPEB_LDR_DATA64;

typedef struct _PEB32
{
	UCHAR				InheritedAddressSpace;
	UCHAR				ReadImageFileExecOptions;
	UCHAR				BeingDebugged;
	UCHAR				BitField;
	ULONG				Mutant;
	ULONG				ImageBaseAddress;
	ULONG				Ldr;
} PEB32, *PPEB32;

typedef struct _PEB64
{
	UCHAR				InheritedAddressSpace;
	UCHAR				ReadImageFileExecOptions;
	UCHAR				BeingDebugged;
	UCHAR				BitField;
	UCHAR				_PADDING0_[0x4];
	VOID*				Mutant;
	VOID*				ImageBaseAddress;
	PPEB_LDR_DATA64		Ldr;
} PEB64, *PPEB64;

BOOLEAN CFORCEINLINE IsListEmpty32(PLIST_ENTRY32 head) { return (BOOLEAN)((PLIST_ENTRY32)head->Flink == head); }
BOOLEAN CFORCEINLINE IsListEmpty64(PLIST_ENTRY64 head) { return (BOOLEAN)((PLIST_ENTRY64)head->Flink == head); }

ULONG CFORCEINLINE ListItemCount32(PLIST_ENTRY32 head)
{
	PLIST_ENTRY32	next;
	ULONG			i = 0;

	for (next = ((PLIST_ENTRY32)head->Flink); next != head; next = ((PLIST_ENTRY32)next->Flink))
		i++;
	return i;
}

ULONG CFORCEINLINE ListItemCount64(PLIST_ENTRY64 head)
{
	PLIST_ENTRY64	next;
	ULONG			i = 0;

	for (next = ((PLIST_ENTRY64)head->Flink); next != head; next = ((PLIST_ENTRY64)next->Flink))
		i++;
	return i;
}

VOID PrintRealDllLoad(HANDLE ProcessId, PUNICODE_STRING module);

NTKERNELAPI PCHAR  NTAPI PsGetProcessImageFileName	(PEPROCESS process);
NTKERNELAPI PPEB64 NTAPI PsGetProcessPeb			(PEPROCESS process);
NTKERNELAPI PPEB32 NTAPI PsGetProcessWow64Process	(PEPROCESS process);
NTKERNELAPI PPEB32 NTAPI PsGetCurrentProcessWow64Process();

NTSTATUS DriverEntry (PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS DriverUnload(PDRIVER_OBJECT DriverObject);

VOID LoadImageNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);

BOOLEAN CFORCEINLINE IsWoW64Process() { return PsGetCurrentProcessWow64Process() != NULL; }

BOOLEAN		IsSourceNtLoader();

ULONG_PTR	GetProcAddress(PVOID base,		PCHAR		name);

BOOLEAN		IsNtDll32(ULONG		 address,	PULONG		base);
BOOLEAN		IsNtDll64(ULONG_PTR  address,	PULONG_PTR	base);