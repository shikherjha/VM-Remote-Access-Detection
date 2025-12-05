#include <windows.h>
#include <iostream>
#include <string>
#include <winternl.h>
#include <TlHelp32.h>
#include <algorithm>
#include <intrin.h> // for __cpuid intrinsic

using namespace std;

bool DetectCPUDIDHypervisor() {
	cout << "[*] Detecting Hypervisor via CPUID..." << endl;

	int cpuInfo[4] = { 0 };
	__cpuid(cpuInfo, 1);

	bool flag = (cpuInfo[2] & (1 << 31)) != 0;  // the 31st bit of ECX is set if there's VM is use

	if (flag) {
		cout << "[!] VM Detected: CPUID Hypervisor bit is set" << endl;

		// Getting the Vendor String
		int vendorInfo[4] = { 0 };
		__cpuid(vendorInfo, 0x40000000);

		char vendor[13] = { 0 };
		memcpy(vendor, &vendorInfo[1], 4); // EBX
		memcpy(vendor + 4, &vendorInfo[2], 4); // ECX
		memcpy(vendor + 8, &vendorInfo[3], 4); //EDX

		cout << "[+] Hypervisor Vendor - " << vendor << endl;
		return true;
	}
	cout << "[-] No Hypervisor string detected" << endl;
	return false;


}
// Checking for the SMBIOS string
bool detectSMBIOS() {
	cout << "[*] Checking for the SMBIOS string...." << endl;

	const wchar_t* smbiosPath[][2] = {
		{L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer"},
		{L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName"},
		{L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVendor"},
		{L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVersion"}
	};
	const wchar_t* vmStrings[] = {
		L"VMware",
		L"VirtualBox",
		L"VBOX",
		L"Virtual",
		L"Hyper-V",
		L"Microsoft Corporation",  // Often Hyper-V
		L"Xen",
		L"QEMU",
		L"innotek",  // Old VirtualBox
		L"Parallels",
		L"KVM"
	};

	for (auto& path : smbiosPath) {
		HKEY hkey;

		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path[0], 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
			wchar_t val[256] = { 0 };
			DWORD size = sizeof(val);
			DWORD type = REG_SZ;

			if (RegQueryValueExW(hkey, path[1], NULL, &type, LPBYTE(val), &size) == ERROR_SUCCESS) {
				wstring valStr = val;
				transform(valStr.begin(), valStr.end(), valStr.begin(), ::tolower);

				for (const wchar_t* curr : vmStrings) {
					wstring vmStr = curr;
					transform(vmStr.begin(), vmStr.end(), vmStr.begin(), ::tolower);

					if (valStr.find(vmStr) != wstring::npos) {
						wcout << L"[!] VM detected: SMBIOS string found - " << path[1] << L"=" << val << endl;
						RegCloseKey(hkey);
						return true;
					}
				}
			}
		}
		RegCloseKey(hkey);
	}
	cout << "[-] No SMBIOS found" << endl;
	return false;
}

// SECTION: ADDING SOME MORE METHODS FOR REMOTE ACCESS DETECTION
bool detectScreenSharing() {
	cout << "[*] Checking for screen sharing processes..." << endl;

	const wchar_t* ssProcesses[] = {
		L"zoom.exe",           // Zoom
		L"teams.exe",          // Microsoft Teams
		L"discord.exe",        // Discord
		L"slack.exe",          // Slack
		L"skype.exe",          // Skype
		L"webexmta.exe",       // Webex
		L"gotomeeting.exe",    // GoToMeeting
		L"obs64.exe",          // OBS Studio (streaming)
		L"obs32.exe",          // OBS Studio 32-bit
		L"streamlabs obs.exe", // Streamlabs
		L"xsplit.core.exe",    // XSplit (streaming)
		L"googleearth.exe"     // Sometimes used for screen sharing
	};

	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (Snapshot == INVALID_HANDLE_VALUE) {
		cout << "[-] No process to enumerate" << endl;
		return false;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32FirstW(Snapshot, &pe32)) {
		CloseHandle(Snapshot);
		return false;
	}
	do {
		wstring curr = pe32.szExeFile;
		transform(curr.begin(), curr.end(), curr.begin(), ::tolower);

		for (const wchar_t* ss : ssProcesses) {
			wstring process = ss;
			transform(process.begin(), process.end(), process.begin(), ::tolower);

			if (process == curr) {
				wcout << L"[!] Remote Access detected: Screen sharing Process - " << pe32.szExeFile << L" ProcessID - " << pe32.th32ProcessID << endl;
				CloseHandle(Snapshot);
				return true;
			}
		}
	} while (Process32NextW(Snapshot, &pe32));
	CloseHandle(Snapshot);
	cout << "[-] No Screen sharing process found" << endl;
	return false;
}


// Now Moving to advanced way to detect VM -> Read Time Stamp counter (RDTSC)
bool detectTimingAttack() {
	cout << "[*] Running time attack..." << endl;
	const int iter = 10;
	int susCnt = 0;
	for (int i = 1; i <= iter; i++) {
		unsigned long long start = __rdtsc();
		for (volatile int j = 0; j < 100; j++);

		unsigned long long end = __rdtsc();

		unsigned long long cycle = end - start;
		cout << "[+] cycle = " << cycle << endl;
		if (cycle > 3000) {
			susCnt++;
			cout << "[!] Suspicious count = " << cycle << " ;Iteration = " << i << endl;
		}
	}
	if (susCnt > iter / 2) {
		cout << "[!] VM detected: Timing anamoly detected" << endl;
		return true;
	}
	cout << "[-] VM not detected via timing attack" << endl;
	return false;
}

int main() {
	bool cpuidDetected = DetectCPUDIDHypervisor();
	bool smbiosDetected = detectSMBIOS();
	bool ssDetected = detectScreenSharing();
	bool rdtscDetected = detectTimingAttack();
	if (cpuidDetected || smbiosDetected || ssDetected || rdtscDetected) {
		cout << "[+] VM detected" << endl;
	}
	else cout << "[-] VM not found" << endl;
}
