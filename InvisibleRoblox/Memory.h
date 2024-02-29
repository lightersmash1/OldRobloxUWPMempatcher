#pragma once

#include <iostream>
#include <Windows.h>
#include <string>
#include <TlHelp32.h>
#include <vector>
#include <regex>
#include <map>

using namespace std;

#if Roblox32BIT
typedef DWORD DWORD00;
#elif
typedef DWORD64 DWORD00;
#endif

HANDLE RobloxInstance;
DWORD00 procId;
DWORD00 Base = 0;
DWORD00 SizeOfR = 0; // Base + Size = the first address in memory that is defined in a stack or allocated. F.Y.I. Between Base and Base + Size is all of the program's assembly and globals. 
BYTE* RobloxMemory;

#if Roblox32BIT 
LPCTSTR RobloxName = L"Windows10Universal.exe";
#else
LPCTSTR RobloxName = L"RobloxPlayerBeta.exe";
#endif
///////////////////////////////////////
vector<string> split(const string& input, const string& regex) {
	// passing -1 as the submatch index parameter performs splitting
	std::regex re(regex);
	std::sregex_token_iterator
		first{input.begin(), input.end(), re, -1},
		last;
	return { first, last };
}

template <typename I> std::string n2hexstr(I w, size_t hex_len = sizeof(I) << 1) {
	static const char* digits = "0123456789ABCDEF";
	std::string rc(hex_len, '0');
	for (size_t i = 0, j = (hex_len - 1) * 4; i < hex_len; ++i, j -= 4)
		rc[i] = digits[(w >> j) & 0x0f];
	return rc;
}
template<typename T = unsigned int>
T Hex2Int(const char* const Hexstr, bool* Overflow = NULL)
{
	if (!Hexstr)
		return false;
	if (Overflow)
		*Overflow = false;

	auto between = [](char val, char c1, char c2) { return val >= c1 && val <= c2; };
	size_t len = strlen(Hexstr);
	T result = 0;

	for (size_t i = 0, offset = sizeof(T) << 3; i < len && (int)offset > 0; i++)
	{
		if (between(Hexstr[i], '0', '9'))
			result = result << 4 ^ Hexstr[i] - '0';
		else if (between(tolower(Hexstr[i]), 'a', 'f'))
			result = result << 4 ^ tolower(Hexstr[i]) - ('a' - 10); // Remove the decimal part;
		offset -= 4;
	}
	if (((len + ((len % 2) != 0)) << 2) > (sizeof(T) << 3) && Overflow)
		*Overflow = true;
	return result;
}
//////////////////////////////////////////////////////
void opbn()
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 pe;
		ZeroMemory(&pe, sizeof(PROCESSENTRY32));
		pe.dwSize = sizeof(PROCESSENTRY32);
		Process32First(hSnap, &pe);
		do
		{
			if (!lstrcmpi(pe.szExeFile, RobloxName))
			{
				procId = pe.th32ProcessID;
				RobloxInstance = OpenProcess(PROCESS_ALL_ACCESS, 0, pe.th32ProcessID);
				cout << "Hooked Roblox with ";
				wcout << RobloxName << endl;
				return;
			}
		} while (Process32Next(hSnap, &pe));
	}
	return;
}

void gbns() {
	HANDLE hmodule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, procId);
	MODULEENTRY32 mEntry;
	mEntry.dwSize = sizeof(mEntry);
	do {
		if (!strcmp((char*)mEntry.szModule, (char*)RobloxName)) {
			CloseHandle(hmodule);
			Base = (DWORD00)mEntry.hModule;
			SizeOfR = mEntry.modBaseSize;
			cout << "Base: " << n2hexstr(Base) << endl;
			cout << "Size: " << n2hexstr(SizeOfR) << endl;
			return;
		}
	} while (Module32Next(hmodule, &mEntry));
	return;
}

template<typename T>
T ReadMemory(DWORD00 Address) {
	T value;
	ReadProcessMemory(RobloxInstance, (LPCVOID)Address, &value, sizeof(T), NULL);
	return value;
}

template<typename T>
T WriteMemory(DWORD00 Address, T Value) {
	T OldValue = ReadMemory<T>(Address);
	WriteProcessMemory(RobloxInstance, (LPVOID)Address, &Value, sizeof(T), 0);
	return OldValue;
}

string ReadMemoryString(std::uintptr_t address) { // skidded pointlessly (i already had one for this purpose)
	string string;
	char character = 0;
	int charSize = sizeof(character);
	int offset = 0;

	string.reserve(52);

	while (offset < 200) { // 200 / sizeof(char) == 50. This means 50 charactes can be read until it will stop reading.
		character = ReadMemory<char>(address + offset);
		if (character == 0) break;
		offset += charSize;
		string.push_back(character);
	}

	return string;
}

template<typename T>
void* CreatePointerToValue(T value) {
	return &value;
}

// for comparing a region in memory, needed in finding a signature
bool MemoryCompare(const BYTE* bData, const BYTE* bMask, const char* szMask) {
	for (; *szMask; ++szMask, ++bData, ++bMask) {
		if (*szMask == 'x' && *bData != *bMask) {
			return false;
		}
	}
	return (*szMask == NULL);
}

// for finding a signature/pattern in memory of another process
vector<DWORD00> FindSignature(const char* sig, const char* mask)
{
	vector<DWORD00> asd;
	for (DWORD00 i = 0; i < SizeOfR; i++)
	{
		if (MemoryCompare((const BYTE*)(RobloxMemory + i), (const BYTE*)sig, mask)) {
			asd.push_back(Base + i);
		}
	}
	return asd;
}
vector<DWORD00> FindSignature2(const char* lol) {
	vector<string> sig2 = split(lol, " ");
	int num = sig2.size();
	BYTE* mask1 = (BYTE*)malloc(num - 1);
	BYTE* sig1 = (BYTE*)malloc(num - 1);
	for (int i = 0; i < num; i++) {
		BYTE a = 'x';
		BYTE numlol = Hex2Int(sig2[i].c_str());
		if (numlol == 0 && sig2[i] != "00") {
			a = '?';
		}
		mask1[i] = a;
		sig1[i] = numlol;
	}
	return FindSignature((const char*)sig1, (const char*)mask1);
}
vector<DWORD00> FindSignature3(string lol) {
	char* mask = (char*)malloc(lol.size());
	for (int i = 0; i < lol.size(); i++) {
		mask[i] = 'x';
	}
	return FindSignature(lol.c_str(), mask);
}
vector<vector<DWORD00>> FindSignature4(vector<const char*> sig, vector<const char*> mask)
{
	vector<vector<DWORD00>> asd;
	for (int i = 0; i < sig.size(); i++) {
		asd.push_back({}); // makes a new array to store stuff
	}
	for (int l = 0; l < sig.size(); l++) {
		cout << l << " start" << endl;
		for (DWORD00 i = 0; i < SizeOfR; i++) {
			if (MemoryCompare((const BYTE*)(RobloxMemory + i), (const BYTE*)sig[l], mask[l])) {
				asd[l].push_back(Base + i);
			}
		}
		cout << l << " finish" << endl;
	}
	return asd;
}
vector<vector<DWORD00>> FindSignature4_2(vector<const char*> lol) {
	vector<const char*> lol123;
	vector<const char*> lol1234;
	for (int poop = 0; poop < lol.size(); poop++) {
		vector<string> sig2 = split(lol[poop], " ");
		int num = sig2.size();
		BYTE* mask1 = (BYTE*)malloc(num - 1);
		BYTE* sig1 = (BYTE*)malloc(num - 1);
		for (int i = 0; i < num; i++) {
			BYTE a = 'x';
			BYTE numlol = Hex2Int(sig2[i].c_str());
			if (numlol == 0 && sig2[i] != "00") {
				a = '?';
			}
			mask1[i] = a;
			sig1[i] = numlol;
		}
		lol123.push_back((const char*)sig1);
		lol1234.push_back((const char*)mask1);
	}
	return FindSignature4(lol123, lol1234);
}
vector<vector<BYTE*>> ReadMemoryByLengths(vector<vector<DWORD00>> things, vector<const char*> lol) {
	vector<vector<BYTE*>> things1;
	for (int i = 0; i < things.size(); i++) {
		things1.push_back({});
		for (int l = 0; l < things[i].size(); l++) {
			size_t sizelol = split(lol[i], " ").size();
			DWORD00 addr = things[i][l];
			BYTE thingasd[256]; // this will be used as a buffer
			ReadProcessMemory(RobloxInstance, (LPCVOID)addr, &thingasd, sizelol, NULL);
			things1[i].push_back(thingasd);
		}
	}
	return things1;
}
void ReplaceAOB(const char* sig, const char* mask, const char* aob2, DWORD00 adder = 0) {
	for (DWORD00 i = 0; i < SizeOfR; i++)
	{
		if (MemoryCompare((const BYTE*)(RobloxMemory + i), (const BYTE*)sig, mask)) {
			WriteProcessMemory(RobloxInstance, (LPVOID)(Base + i - adder), &aob2, sizeof(aob2), 0);
		}
	}
}

void ReplaceAOB2(const char* lol, const char* lol2, DWORD00 adder = 0) {
	vector<string> sig2 = split(lol, " ");
	int num = sig2.size();
	BYTE* mask1 = (BYTE*)malloc(num - 1);
	BYTE* sig1 = (BYTE*)malloc(num - 1);
	for (int i = 0; i < num; i++) {
		BYTE a = 'x';
		BYTE numlol = Hex2Int(sig2[i].c_str());
		if (numlol == 0 && sig2[i] != "00") {
			a = '?';
		}
		mask1[i] = a;
		sig1[i] = numlol;
	}
	ReplaceAOB((const char*)sig1, (const char*)mask1, lol2, adder);
}