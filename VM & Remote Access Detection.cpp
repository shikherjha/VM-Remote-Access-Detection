#include <windows.h>
#include <iostream>
#include <string>
#include <winternl.h>
#include <TlHelp32.h>
#include <algorithm>

using namespace std;

// check common VM registry
bool DetectVMRegistry() {
	cout << "[*] Detecting VM related registry...." << "\n";

	const wchar_t* RegKeys[] = {
		L"HARDWARE\\ACPI\\DSDT\\VBOX__",           // VirtualBox
		L"HARDWARE\\ACPI\\DSDT\\VMWARE__",         // VMware
		L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemManufacturer", // Generic
		L"SOFTWARE\\VMware, Inc.\\VMware Tools"    // VMware Tools
	};
	for (const wchar_t* key : RegKeys) {
		HKEY hKey;

		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
			cout << "[!] VM Detected: Registy key found - " << endl;
			RegCloseKey(hKey);
			return true;
		}
	}
	cout << "[-] VM not detected: No Registry key found - " << endl;
	return false;
}

// Detect VM specific Files
bool DetectVMFiles() {
	cout << " [*] Detecting VM related files....... " << endl;

	const wchar_t* VMFiles[] = {
		L"C:\\Windows\\System32\\drivers\\vmmouse.sys",   // VMware mouse
		L"C:\\Windows\\System32\\drivers\\vmhgfs.sys",    // VMware shared folders
		L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys", // VirtualBox mouse
		L"C:\\Windows\\System32\\drivers\\VBoxGuest.sys", // VirtualBox guest
		L"C:\\Windows\\System32\\vboxdisp.dll",           // VirtualBox display
		L"C:\\Windows\\System32\\vboxhook.dll"            // VirtualBox hook
	};

	for (const wchar_t* file : VMFiles) {
		DWORD attr = GetFileAttributesW(file);

		if (attr != INVALID_FILE_ATTRIBUTES) {
			wcout << L"[!] VM detected: File detected -" << file << endl;
			return true;
		}
	}
	cout << " [-] VM not detected: No VM file found - " << endl;
	return false;
}

// Checking for running processes for VM
bool DetectVMProcesses() {
	cout << " [*] Detecting VM based Processes...... " << endl;
	const wchar_t* VMProcesses[] = {
		L"vmtoolsd.exe",     // VMware Tools
		L"vmwaretray.exe",   // VMware Tray
		L"vmwareuser.exe",   // VMware User Process
		L"vboxservice.exe",  // VirtualBox Service
		L"vboxtray.exe",     // VirtualBox Tray
		L"xenservice.exe"    // Xen
	};

	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Snapshot == INVALID_HANDLE_VALUE) {
		wcout << " [-] No process to enumerate " << endl;
		return false;
	}

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(Snapshot, &pe32)) {
		CloseHandle(Snapshot);
		return false;
	}

	do {
		wstring ExistingProcess = pe32.szExeFile;// szExeFile hold the name of the process  PROCESSENTRY32W
		transform(ExistingProcess.begin(), ExistingProcess.end(), ExistingProcess.begin(), ::tolower);

		for (const wchar_t* VMP : VMProcesses) {
			wstring CurrentProcess = VMP;
			transform(CurrentProcess.begin(), CurrentProcess.end(), CurrentProcess.begin(), ::tolower);

			if (CurrentProcess == ExistingProcess) {
				wcout << L" [!] VM detected: Process found - " << pe32.szExeFile << endl;
				CloseHandle(Snapshot);
				return true;
			}
		}


	} while (Process32NextW(Snapshot, &pe32));

	CloseHandle(Snapshot);
	cout << " [-] No VM Process detected" << endl;
	return false;
}

// Now section-2 Checking for Remote Access Control

// Checking Remote Desktop Protocol (RDP)
bool DetectRDP() {
	cout << "[*] Checking for RDP session....." << endl;

	if (GetSystemMetrics(SM_REMOTESESSION)) {
		cout << "[!] Remote Access detected: RDP Session" << endl;
		return true;
	}
	else {
		cout << "[-] No RDP session Detected" << endl;
		return false;
	}
}

// Checking for Remote Access Software process
bool DetectRemoteAccessTools() {
	cout << "[*] Detecting Remote access Software Process.....  " << endl;

	const wchar_t* RASProcess[] = {
		L"teamviewer.exe",   // TeamViewer
		L"anydesk.exe",      // AnyDesk
		L"tvnserver.exe",    // TightVNC Server
		L"vncviewer.exe",    // VNC Viewer
		L"msra.exe",         // Windows Remote Assistance
		L"chrome.exe",       // Could be Chrome Remote Desktop
		L"logmein.exe"       // LogMeIn
	};

	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Snapshot == INVALID_HANDLE_VALUE) {
		cout << "[-] No process to enumerate" << endl;
		CloseHandle(Snapshot);
		return false;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(Snapshot, &pe32)) {
		CloseHandle(Snapshot);
		return false;
	}

	do {
		wstring ProcessName = pe32.szExeFile;
		transform(ProcessName.begin(), ProcessName.end(), ProcessName.begin(), ::tolower);

		for (const wchar_t* Process : RASProcess) {
			wstring CurrentProcess = Process;
			transform(CurrentProcess.begin(), CurrentProcess.end(), CurrentProcess.begin(), ::tolower);

			if (CurrentProcess == ProcessName) {
				wcout << L"[!] Remote Access Detected : Process found - " << pe32.szExeFile << endl;
				CloseHandle(Snapshot);
				return true;
			}
		}
	} while (Process32Next(Snapshot, &pe32));
	CloseHandle(Snapshot);
	cout << "[-] No Remote Access Process Detected " << endl;
	return false;
}


int main() {
	cout << "================================================" << endl;
	cout << "   VM & Remote Access Detection System v1.0" << endl;
	cout << "================================================" << endl;
	cout << endl;

	bool vmDetected = false;
	bool remoteDetected = false;

	cout << ">>> RUNNING VM DETECTION CHECKS <<<" << endl;
	cout << endl;
	if (DetectVMRegistry()) vmDetected = true;
	if (DetectVMFiles()) vmDetected = true;
	if (DetectVMProcesses()) vmDetected = true;

	cout << endl;

	cout << ">>> RUNNING REMOTE ACCESS DETECTION CHECKS <<<" << endl;
	cout << endl;

	if (DetectRDP()) remoteDetected = true;
	if (DetectRemoteAccessTools()) remoteDetected = true;

	cout << endl;
	cout << "================================================" << endl;
	cout << "   DETECTION SUMMARY" << endl;
	cout << "================================================" << endl;

	if (vmDetected) {
		cout << "[!!!] ALERT: Virtual Machine environment detected!" << endl;
	}
	else {
		cout << "[OK] No VM environment detected" << endl;
	}

	if (remoteDetected) {
		cout << "[!!!] ALERT: Remote access detected!" << endl;
	}
	else {
		cout << "[OK] No remote access detected" << endl;
	}

	cout << endl;

	// Keep console open
	cout << "Press Enter to exit...";
	cin.get();

	return 0;
}