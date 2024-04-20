#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#define MAX_API_SIZE 128

class HOOK
{
public:

	static int Hook(HANDLE hProcess , std::string& To_hook , uint64_t New_function);
private:

};


typedef struct IMPORT_TABLE_ENTRY {
	DWORD RVA_LOOKUP_TABLE;
	DWORD DATA_STAMP;
	DWORD FORWARDER_CHAIN;
	DWORD RVA_NAME;
	DWORD RVA_IAT;
}IMPORT_TABLE_ENTRY;

typedef struct NAME_TABLE {
	WORD Hint;
	char API_NAME[MAX_API_SIZE];
}NAME_TABLE;
