#include "pch.h"
#include "Injector.h"
#include "Hook.h"
#include <string>
#include <filesystem>
#include <iostream>
#include <TlHelp32.h>

bool IsDll(const char* dllName) {
	return LoadLibraryA(dllName) ? true : false;
}

int main(int argc, const char* argv[]) {
	
	if (argc < 3) {
		std::cout << "Usage :" << argv[0] << " <process_id> <dll>" << std::endl;
		return EXIT_FAILURE;
	}

	if (!std::filesystem::exists(argv[2])) {
		std::cout << "File " << argv[2] << " does not exist in the working directory !" << std::endl;
		return EXIT_FAILURE;
	}

	if (!IsDll(argv[2])) {
		std::cout << "ERROR :The specified file isnt a dll file !" << std::endl;
		return EXIT_FAILURE;
	}
	DWORD dwProcessId = atoi(argv[1]);
	bool bPidVerified = false;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		goto START;
	}
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &pe32)) {
		goto START;
	}

	do {
		if (pe32.th32ProcessID == dwProcessId) {
			bPidVerified = true;
			goto START;
		}
	} while (Process32Next(hSnapshot , &pe32));

	if (!bPidVerified) {
		std::cout << "ERROR :No suck process !" << std::endl;
		return EXIT_FAILURE;
	}

START:
	// We can change the desired access to PROCESS_VM_READ|PROCESS_VM_WRITE

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwProcessId);
	if (hProcess == INVALID_HANDLE_VALUE) {
		std::cout << "ERROR :Could not open the desired process , consider checking your permissions !" << std::endl;
		return EXIT_FAILURE;
	}

	std::string dllPath(argv[2]);
	bool  Status  = Injector::InjectDll(hProcess, dllPath);
	if (!Status) {
		std::cout << "ERROR :Could not Inject the specified dll in the process" << std::endl;
		return EXIT_FAILURE;
	}
	std::cout << "Dll Injected Successfully" << std::endl;
	std::string to_hook("GetCurrentProcessId");
	std::string copy_t(to_hook);
	HMODULE hModule= GetModuleHandleA(dllPath.c_str());
	if (hModule == INVALID_HANDLE_VALUE) {
		std::cout << "WTF" << std::endl;
		return EXIT_FAILURE;
	}
	to_hook.append("_h");
	FARPROC Address = GetProcAddress(hModule, to_hook.c_str());
	if (Address == NULL) {
		std::cout << to_hook.c_str() << std::endl;
		std::cout << GetLastError() << std::endl;
	}
	
	Status = HOOK::Hook(hProcess, copy_t, (uint64_t)Address);
	if (!Status) {
		std::cout << "ERROR :Could not Hook " << argv[2] <<" !"<< std::endl;
		return EXIT_FAILURE;
	}
	
	return EXIT_SUCCESS;
}