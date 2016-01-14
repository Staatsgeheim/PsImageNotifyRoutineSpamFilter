/*
	PsImageNotifyRoutine Spam Filter v1.0

	Copyright (c) 2015 Maarten Boone
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

#include "Main.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(PAGE, LoadImageNotify)
#pragma alloc_text(PAGE, IsSourceNtLoader)
#pragma alloc_text(PAGE, IsNtDll32)
#pragma alloc_text(PAGE, IsNtDll64)
#pragma alloc_text(PAGE, GetProcAddress)
#pragma alloc_text(PAGE, PrintRealDllLoad)
#endif

#pragma data_seg("PAGEDATA")
#pragma bss_seg("PAGEBSS")
static BOOLEAN	LoadImageNotifyActive = FALSE;
static ULONG	LdrLoadDllOffset32 =	0;
static ULONG	LdrLoadDllOffset64 =	0;

static UCHAR	LdrLoadDll[] =			{ "LdrLoadDll" };
static UCHAR	DbgPrintText[] =		{ "[%08X] %s LdrLoadDll: %wZ" };
#pragma data_seg()
#pragma bss_seg()

VOID PrintRealDllLoad(HANDLE ProcessId, PUNICODE_STRING module)
{
	DbgPrint((PCHAR)&DbgPrintText, ProcessId, PsGetProcessImageFileName(PsGetCurrentProcess()), module);
}

BOOLEAN IsSourceNtLoader()
{
	__try
	{
		PVOID Trace[2 * MAX_STACK_DEPTH];
		ULONG FramesFound = RtlWalkFrameChain(Trace, FramesToCapture + FramesToSkip, USER_MODE_STACK);

		if (FramesFound <= FramesToSkip)
		{
			if (FramesFound == FramesToSkip)	// Process is initializing, log the first 2 or 3(WoW64) entries
				return TRUE;
			return FALSE;
		}

		for (ULONG i = FramesToSkip; i < FramesToCapture + FramesToSkip; i++)
		{
			if (i >= FramesFound)
				break;
			else if (!Trace[i])
				break;

			ULONG		NtDllBase32;
			ULONG_PTR	NtDllBase64;
			ULONG_PTR	Entry = ((ULONG_PTR)Trace[i]);

			if (IsWoW64Process())
			{
				if (IsNtDll32((ULONG)Entry, &NtDllBase32))
				{
					if (Entry >= (ULONG_PTR) (NtDllBase32 + LdrLoadDllOffset32) &&
						Entry <= (ULONG_PTR)((NtDllBase32 + LdrLoadDllOffset32) + LdrLoadDllSize))
					{
						return TRUE;
					}
				}
				// Could be the WoW64 subsystem loading
				else if (IsNtDll64(Entry, &NtDllBase64))
				{
					if (Entry >= (ULONG_PTR) (NtDllBase64 + LdrLoadDllOffset64) &&
						Entry <= (ULONG_PTR)((NtDllBase64 + LdrLoadDllOffset64) + LdrLoadDllSize))
					{
						return TRUE;
					}
				}
			}
			else if (IsNtDll64(Entry, &NtDllBase64))
			{
				if (Entry >= (ULONG_PTR) (NtDllBase64 + LdrLoadDllOffset64) &&
					Entry <= (ULONG_PTR)((NtDllBase64 + LdrLoadDllOffset64) + LdrLoadDllSize))
				{
					return TRUE;
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { }
	return FALSE;
}

VOID LoadImageNotify(PUNICODE_STRING FullImageName,	HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	if (!(ImageInfo->SystemModeImage))
		if (IsSourceNtLoader())
			PrintRealDllLoad(ProcessId, FullImageName);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status;

	DriverObject->DriverUnload = DriverUnload;

	status = PsSetLoadImageNotifyRoutine(LoadImageNotify);
	if (NT_SUCCESS(status))
		LoadImageNotifyActive = TRUE;

	return status;
}

NTSTATUS DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	NTSTATUS status = STATUS_SUCCESS;

	if (LoadImageNotifyActive)
		PsRemoveLoadImageNotifyRoutine(LoadImageNotify);

	return status;
}

// This function checks if the current stackframe is located inside the Ntdll WoW64 binary
// if that's the case check if the caller was LdrLoadDll
BOOLEAN IsNtDll32(ULONG address, PULONG base)
{
	PPEB_LDR_DATA32			Ldr;
	PLDR_DATA_TABLE_ENTRY32 Entry;
	
	Ldr = ((PPEB_LDR_DATA32)PsGetProcessWow64Process(PsGetCurrentProcess())->Ldr);

	if (!Ldr)		// This can happen while the WoW64 subsystem is still initializing
		return FALSE;

	if (IsListEmpty32((PLIST_ENTRY32)Ldr->InLoadOrderModuleList.Flink))	
		return FALSE;

	if (ListItemCount32((PLIST_ENTRY32)Ldr->InLoadOrderModuleList.Flink) == 1)
		return FALSE;
	
	Entry = (PLDR_DATA_TABLE_ENTRY32)Ldr->InLoadOrderModuleList.Flink;	// Main exe
	Entry = (PLDR_DATA_TABLE_ENTRY32)Entry->InLoadOrderLinks.Flink;		// Ntdll

	if (((ULONG_PTR)address >= (ULONG_PTR)Entry->DllBase) &&
		((ULONG_PTR)address < ((ULONG_PTR)Entry->DllBase + Entry->SizeOfImage)))
	{
		if (!LdrLoadDllOffset32)
			 LdrLoadDllOffset32 = (ULONG)(GetProcAddress((PVOID)Entry->DllBase, (PCHAR)&LdrLoadDll) - Entry->DllBase);	// Only called once

		*base = Entry->DllBase;
		return TRUE;
	}
	return FALSE;
}

// This function checks if the current stackframe is located inside the Ntdll 64 bits binary
// if that's the case check if the caller was LdrLoadDll
BOOLEAN IsNtDll64(ULONG_PTR address, PULONG_PTR base)
{
	PPEB_LDR_DATA64			Ldr;
	PLDR_DATA_TABLE_ENTRY64 Entry;
	
	Ldr = ((PPEB_LDR_DATA64)PsGetProcessPeb(PsGetCurrentProcess())->Ldr);

	if (IsListEmpty64((PLIST_ENTRY64)Ldr->InLoadOrderModuleList.Flink))
		return FALSE;

	if (ListItemCount64((PLIST_ENTRY64)Ldr->InLoadOrderModuleList.Flink) == 1)
		return FALSE;

	Entry = (PLDR_DATA_TABLE_ENTRY64)Ldr->InLoadOrderModuleList.Flink;	// Main exe
	Entry = (PLDR_DATA_TABLE_ENTRY64)Entry->InLoadOrderLinks.Flink;		// Ntdll

	if (((ULONG_PTR)address >= (ULONG_PTR)Entry->DllBase) &&
		((ULONG_PTR)address < ((ULONG_PTR)Entry->DllBase + Entry->SizeOfImage)))
	{
		if (!LdrLoadDllOffset64)
			 LdrLoadDllOffset64 = (ULONG)(GetProcAddress((PVOID)Entry->DllBase, (PCHAR)&LdrLoadDll) - (ULONG_PTR)Entry->DllBase);	// Only called once

		*base = (ULONG_PTR)Entry->DllBase;
		return TRUE;
	}
	return FALSE;
}

ULONG_PTR GetProcAddress(PVOID base, PCHAR name)
{
	PIMAGE_DOS_HEADER		dosHeader			= (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS32		ntHeaders32			= NULL;
	PIMAGE_NT_HEADERS64		ntHeaders64			= NULL;
	PIMAGE_EXPORT_DIRECTORY exportDirectory		= NULL;
	ULONG					exportDirectorySize = 0;
	ULONG_PTR				functionAddress		= 0;

	ASSERT(base != NULL);
	if (base == NULL)
		return 0;
		
	__try
	{
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		ntHeaders32 = (PIMAGE_NT_HEADERS32)((PUCHAR)base + dosHeader->e_lfanew);
		ntHeaders64 = (PIMAGE_NT_HEADERS64)((PUCHAR)base + dosHeader->e_lfanew);

		if (ntHeaders32->Signature != IMAGE_NT_SIGNATURE)
			return 0;

		if (ntHeaders64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			exportDirectory =		(PIMAGE_EXPORT_DIRECTORY)(ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)base);
			exportDirectorySize =	ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		}
		else
		{
			exportDirectory =		(PIMAGE_EXPORT_DIRECTORY)(ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)base);
			exportDirectorySize =	ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		}

		PUSHORT AddressOfNameOrdinals = (PUSHORT)(exportDirectory->AddressOfNameOrdinals +	(ULONG_PTR)base);
		PULONG  AddressOfNames =		(PULONG) (exportDirectory->AddressOfNames +			(ULONG_PTR)base);
		PULONG  AddressOfFunctions =	(PULONG) (exportDirectory->AddressOfFunctions +		(ULONG_PTR)base);

		for (ULONG i = 0; i < exportDirectory->NumberOfFunctions; ++i)
		{
			USHORT functionOrdinal =	AddressOfNameOrdinals[i];
			PCHAR  functionName	=		functionName = (PCHAR)(AddressOfNames[i] + (ULONG_PTR)base);
						
			if (strcmp(functionName, name) == 0)
			{
				functionAddress = AddressOfFunctions[functionOrdinal] + (ULONG_PTR)base;
				break;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { }
	return functionAddress;
}

