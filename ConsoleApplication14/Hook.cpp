#include "pch.h"
#include "Hook.h"
#include <windows.h>
#include <stdlib.h>
#include <iostream>
#include <psapi.h>
#include <cstdio>
#include <cstdint>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

char * GetProcessFileName(HANDLE hProcess) {
	char* name = new char[_MAX_PATH];
	GetModuleFileNameExA(hProcess, NULL, name, _MAX_PATH);
	return PathFindFileNameA(name);
}

int HOOK::Hook(HANDLE hProcess , std::string& To_hook , uint64_t New_function)
{
	
	IMPORT_TABLE_ENTRY entry;
	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS ntHeaders;

	HMODULE lphModules[1024];
	CHAR lpBaseName[_MAX_PATH];	
	HMODULE hModule; 
	DWORD cbNeeded;

	MODULEINFO modInfo; 
	
	if (!EnumProcessModules(hProcess, lphModules, sizeof(lphModules), &cbNeeded)) {
		std::cout << "ERROR: EnumProcessModules" << std::endl;
		return false;
		
	}
	for (auto module_i = 0; module_i < cbNeeded / sizeof(HMODULE); module_i++) {
		GetModuleBaseNameA(hProcess, lphModules[module_i], lpBaseName, _MAX_PATH);
		if (!strcmp(lpBaseName, GetProcessFileName(hProcess))) {
			hModule = lphModules[module_i];
			break;
		}
	}
	if (!GetModuleInformation(hProcess, hModule, &modInfo, sizeof(modInfo))) {
		return false;
	}
	uintptr_t processBaseAddress = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);

	if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(modInfo.lpBaseOfDll), &dosHeader,sizeof(IMAGE_DOS_HEADER), NULL)) {
		std::cout << "ERROR: DOS HEADER" << std::endl;
		return false;
	}

	if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(processBaseAddress + dosHeader.e_lfanew), &ntHeaders, sizeof(IMAGE_NT_HEADERS), NULL)) {
		std::cout << "ERROR: NT HEADERS" << std::endl;
		return false;
	}
	IMAGE_DATA_DIRECTORY imDataDir  = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	DWORD i = 0;
	DWORD j = 0;
	DWORD k = 0;
	uint64_t  RVA_LOOKUP_ENTRY = 0;
	NAME_TABLE nmTable;
	while (i < imDataDir.Size / sizeof(IMPORT_TABLE_ENTRY) - 1) {
		if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(processBaseAddress + imDataDir.VirtualAddress + i * sizeof(IMPORT_TABLE_ENTRY)), &entry, sizeof(IMPORT_TABLE_ENTRY), NULL)) {
			std::cout << "ERROR: IMPORT DIRECTORY" << std::endl;
			return false;
		}
		
		do{

			SEARCH_NAME_NOT_ORDINAL:
			if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(processBaseAddress + entry.RVA_LOOKUP_TABLE + k*8), &RVA_LOOKUP_ENTRY, sizeof(uint64_t), NULL)) {
				std::cout << "ERROR: RVA LOOKUP" << std::endl;
				return false;
			}

			// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-lookup-table
			if (RVA_LOOKUP_ENTRY & 0x80000000) goto SEARCH_NAME_NOT_ORDINAL;
			if (RVA_LOOKUP_ENTRY == 0) break;
			if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(processBaseAddress + RVA_LOOKUP_ENTRY ),&nmTable,sizeof(NAME_TABLE) , NULL)) {
				std::cout << "ERROR: NAME TABLE" << std::endl;
				return false;
			}
			if (!strcmp(nmTable.API_NAME, To_hook.c_str())) goto READ_WRITE_rdata;
			k++;

		} while (RVA_LOOKUP_ENTRY);

		i++;
	}

	
	READ_WRITE_rdata:
		DWORD dwSection = 1;
		
		IMAGE_SECTION_HEADER* sectionHeaders = new IMAGE_SECTION_HEADER[ntHeaders.FileHeader.NumberOfSections];
		if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(processBaseAddress + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS)), sectionHeaders, ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), NULL)) {
			std::cout << "ERROR: Section headers" << std::endl;
		}
	
		while (dwSection < ntHeaders.FileHeader.NumberOfSections) {
			if (!strcmp((char*)sectionHeaders->Name, ".rdata")) {
				break;
			}
			dwSection++;
			sectionHeaders++;
		}
		DWORD dwOldProtection;
		if (dwSection == ntHeaders.FileHeader.NumberOfSections + 1) {
			std::cout << "ERROR: .rdata" << std::endl;
			return false;
		}
		if (!VirtualProtectEx(hProcess, (LPVOID)(processBaseAddress + sectionHeaders->VirtualAddress), sectionHeaders->Misc.VirtualSize, PAGE_READWRITE, &dwOldProtection)) {
			std::cout << "ERROR: VirtualProtectEx" << std::endl;
			return false;
		}

	// Start debugging
	uint64_t API_ADDRESS; 
	if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(processBaseAddress + entry.RVA_IAT + 8 * k), &API_ADDRESS, sizeof(uint64_t), NULL)) {
		std::cout << "Error :Getting Address" <<std::endl;
		return false;
	}
	// End Debugging
	if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(processBaseAddress + entry.RVA_IAT + 8 * k), &New_function, sizeof(uint64_t), NULL)) {
		std::cout << GetLastError() << std::endl;
		return false;
	}
	return true;
}
