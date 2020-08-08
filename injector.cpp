#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <string>

class Injector
{
public:
	DWORD pID;
	LPCSTR DllPath;
	HANDLE hProcess;
	LPVOID pDllPath;
	HANDLE hLoadThread;

public:
	int GetProcessId(LPCTSTR ProcessName) // non-conflicting function name
	{
		PROCESSENTRY32 pt;
		HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pt.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hsnap, &pt)) { // must call this first
			do {
				if (!lstrcmpi(pt.szExeFile, ProcessName)) {
					CloseHandle(hsnap);
					pID = pt.th32ProcessID;
					return 1;
				}
			} while (Process32Next(hsnap, &pt));
		}
		CloseHandle(hsnap); // close handle on failure
		return 0;
	}

	std::string ExePath() {
		char buffer[MAX_PATH];
		GetModuleFileName(NULL, buffer, MAX_PATH);
		std::string::size_type pos = std::string(buffer).find_last_of("\\/");
		std::string cesta;
		cesta = std::string(buffer).substr(0, pos);
		return cesta.append("\\");
	}

	void getHandle(DWORD processID)
	{
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	}

	void AllocateMemory()
	{
		pDllPath = VirtualAllocEx(hProcess, 0, strlen(DllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	}

	void WritePathToMemory()
	{
		WriteProcessMemory(hProcess, pDllPath, (LPVOID)DllPath, strlen(DllPath) + 1, 0);
	}

	void CreateThread()
	{
		hLoadThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"), pDllPath, 0, 0);
	}

	void WaitForThreadFinish()
	{
		WaitForSingleObject(hLoadThread, INFINITE);
	}
};


int main(int argc, char *argv[])
{
	Injector Injector;

	if (argc != 3)
	{
		std::cout << "Usage: injector.exe [process.exe] [yourdll.dll]" << std::endl;
		return 0;
	}
	else
	{
		std::string cestaDll = Injector.ExePath();
		cestaDll.append(argv[2]);
		LPCSTR long_string = cestaDll.c_str();
		Injector.DllPath = long_string;

		std::cout << "Injecting " << Injector.DllPath << " into " << argv[1] << std::endl;

		Injector.GetProcessId(TEXT(argv[1]));
		Injector.getHandle(Injector.pID);

		if (Injector.hProcess == NULL)
		{
			std::cout << "Failed to get handle!" << std::endl;
			return 1;
		}

		Injector.AllocateMemory();
		Injector.WritePathToMemory();
		Injector.CreateThread();

		Injector.WaitForThreadFinish();

		std::cout << Injector.DllPath << "  " << Injector.pID << std::endl;
		std::cout << "Dll path allocated at: " << std::hex << Injector.pDllPath << std::endl;
		std::cin.get();

		VirtualFreeEx(Injector.hProcess, Injector.pDllPath, strlen(Injector.DllPath) + 1, MEM_RELEASE);

	}

	return 1;
}