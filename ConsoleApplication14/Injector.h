#pragma once
#include <windows.h>
#include <string>

class Injector
{
public:
	static bool InjectDll(HANDLE hProcess, std::string& dllPath);
private:
};
