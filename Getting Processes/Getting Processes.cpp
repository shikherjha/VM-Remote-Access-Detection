#include <windows.h>
#include <iostream>
#include <string>
#include <winternl.h>
#include <TlHelp32.h>
#include <algorithm>

using namespace std;

// Fecthing and printing all the running processes
void ListProcesses() {
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Snapshot == INVALID_HANDLE_VALUE) {
		cout << "[-] Unable to create a process snapshot." << endl;
		//CloseHandle(Snapshot);
		return;
	}

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(Snapshot, &pe32)) {
		cout << "[!] Error Fetching the process" << endl;
		CloseHandle(Snapshot);
		return;
	}

	do {
		wcout << L"[+] Process - " << pe32.szExeFile << " Process ID -" << pe32.th32ProcessID << endl;
	} while (Process32NextW(Snapshot, &pe32));
	CloseHandle(Snapshot);

	cout << "[-] ALL the running process listed!" << endl;
}
int main() {
	ListProcesses();
	return 0;
}