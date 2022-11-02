#include<Windows.h>
#include<psapi.h>
#include<TlHelp32.h>
#include<iostream>
#include<string>

//global variables
//
HANDLE process = NULL;
DWORD procID = 0;
HMODULE hMods[1024]; //maximum value to store as much modules as necessary
unsigned int modulesinapp = 0;

// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

bool getprocess(char* processname)
{
	HANDLE processSnap;
	PROCESSENTRY32 proc32;
	DWORD procid;

	proc32.dwSize = sizeof(PROCESSENTRY32);
	processSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (processSnap == INVALID_HANDLE_VALUE)
	{
		std::cout << "INVALID_HANDLE_VALUE" << std::endl;
		return false;
	}

	while (Process32Next(processSnap, &proc32))
	{
		if (!strcmp(processname, proc32.szExeFile)) //dont forget to go to project properties > advanced > character set > multi-byte
		{
			process = OpenProcess(PROCESS_ALL_ACCESS, false, proc32.th32ProcessID);
			procid = proc32.th32ProcessID;
			procID = proc32.th32ProcessID;
			if (process == NULL)
			{
				std::cout << "failed to get the process" << std::endl;
			}
			CloseHandle(processSnap);
			return true;
		}
	}
	CloseHandle(processSnap);
	std::cout << "process not found" << std::endl;
	return false;
}


int PrintModules(DWORD processID)
{
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	// Get a handle to the process.

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
	if (NULL == hProcess)
		return 1;

	// Get a list of all the modules in this process.

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				// Print the module name and handle value.
				modulesinapp++;
			}
		}
	}

	// Release the handle to the process.

	CloseHandle(hProcess);

	return 0;
}

//Get all module related info, this will include the base DLL.
//and the size of the module
MODULEINFO GetModuleInfo(HMODULE hModule)
{
	MODULEINFO modinfo = { 0 };
	if (hModule == 0) return modinfo;
	GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
	return modinfo;
}

int main()
{
	//
	//part that will treat the input and turn it into the otput needed to search for the process 
	std::cout << "Insert the name of the executable you want to open :> ";
	std::string procname;
	std::cin >> procname;
	char* processname = const_cast<char*>(procname.c_str());
	getprocess(processname);
	PrintModules(procID);
	printf("%d modules inside this executable \n", modulesinapp);


	int y = 0;
	int module_number = 0;
	while (y <= modulesinapp)
	{
		y++;
		module_number++;
		//
		//testing only ac_client.exe - everything worked fine - the problem is in fstream / exporting to .txt
		MODULEINFO mInfoinside = GetModuleInfo(hMods[y]);
		DWORD baseinside = (DWORD)mInfoinside.lpBaseOfDll;
		DWORD sizeinside = (DWORD)mInfoinside.SizeOfImage;
		DWORD entryinside = (DWORD)mInfoinside.EntryPoint;

		//
		// Opening the process with permitions  specified and storing this address into a handle
		HANDLE curproc = OpenProcess(PROCESS_QUERY_INFORMATION |
			PROCESS_VM_READ,
			FALSE, GetCurrentProcessId()); //used to be FALSE - testing right now

		TCHAR szModName[MAX_PATH];

		//
		// Get the full path to the module's file.
		GetModuleFileNameEx(curproc, hMods[y], szModName, sizeof(szModName) / sizeof(TCHAR));

		//
		//printing modules path inside application and their size.          
		printf(TEXT("\t%s (0x%08X)\t Module name: %d\n"), szModName, hMods[y], module_number);
		//
	}
	//const wchar_t* szName = name.c_str();
	//printf("%c", procname);
	std::cout << procname;
	//GetProcId(finalexecname);
	//PrintModules();

	// free((void*)finalexecname);
	return 0;
}