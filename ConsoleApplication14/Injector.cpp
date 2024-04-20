#include "pch.h"
#include "Injector.h"
bool Injector::InjectDll(HANDLE hProcess, std::string& dllPath) {
    HANDLE hThread;
    void* pLibRemote = 0;

    HMODULE hKernel32 = GetModuleHandle(L"kernel32");
    HINSTANCE hInst = GetModuleHandle(NULL);

    char DllFullPathName[_MAX_PATH];
    GetFullPathNameA(dllPath.c_str(), _MAX_PATH, DllFullPathName, NULL);

    char szLibPath[_MAX_PATH];
    strcpy_s(szLibPath, DllFullPathName);

    pLibRemote = VirtualAllocEx(hProcess, NULL, sizeof(szLibPath), MEM_COMMIT, PAGE_READWRITE);
    if (pLibRemote == NULL) {
        return false;
    }
    WriteProcessMemory(hProcess, pLibRemote, (void*)szLibPath, sizeof(szLibPath), NULL);

    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA"), pLibRemote, 0, NULL);
    return (hThread == NULL) ? false : true;
}