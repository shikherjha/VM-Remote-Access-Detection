#include <windows.h>
#include <iostream>
#include <string>
#include <winternl.h>
#include <TlHelp32.h>
using namespace std;

// Fetching all the running processes
int main() {
	cout << "[*] Fetching all the running processes..... " << endl;
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Snapshot == INVALID_HANDLE_VALUE) {
		cout << "[-] No process to enumerate" << endl;
		CloseHandle(Snapshot);
	}

	PROCESSENTRY32W pe32;
	pe32.dwsize = sizeof(PROCESSENTRY32);

	if (!Process32First(Snapshot, &pe32) {
		cout << "[-] No process found" << endl;
	}
	do {
		wcout << L"[+] Process Name - " << endl;
	}while(Process32Next(Snapshot,&pe32));
	CloseHandle(Snapshot);

	return 0;
}