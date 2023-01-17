#include<Windows.h>
#include<psapi.h>
#include<TlHelp32.h>
#include<iostream>
#include<string>



//
//Project IDEA so far
 
// - CHECK 1 DONE
//receive user input(executable name) - search for it - find the process ID

// - CHECK 2 DONE
//run the printmodules, list the modules inside the application

// - DO DONE
//ask for the specified module name to list what its loading in memory
//solved with module number

// DONE
//create a static menu where you restart the search, Getasynckeystate - something to restart the app
//solved with goto statemant way easier but unsafe in case of bufferoverflow, i thought about using assembly directly into it

//
//Macros
#define MEMO_PROTEC (PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_READWRITE| PAGE_EXECUTE_READWRITE)

//
//global variables
HANDLE process = NULL;
DWORD procID = 0;
HMODULE hMods[1024]; //maximum value to store as much modules as necessary
unsigned int modulesinapp = 0;
DWORD ModulesAddreessess[MAX_PATH];

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

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
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
				// counter for modules inside
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
	GetModuleInformation(process, hModule, &modinfo, sizeof(MODULEINFO));
	return modinfo;
}

//
//function that i adapted from msdn
int ModuleLister(int module_number_input)
{	

	MODULEINFO mInfoinside = GetModuleInfo(hMods[module_number_input]);
	DWORD baseinside = (DWORD)mInfoinside.lpBaseOfDll;
	DWORD sizeinside = (DWORD)mInfoinside.SizeOfImage;
	DWORD entryinside = (DWORD)mInfoinside.EntryPoint;

	int i = 0;

	HANDLE curproc = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE, procID); //used to be FALSE - testing right now

	TCHAR szModName[MAX_PATH];
	DWORD nbuffer;

	//
	// Get the full path to the module's file.
	GetModuleFileNameEx(curproc, hMods[module_number_input], szModName, sizeof(szModName) / sizeof(TCHAR));



	while (i <= sizeinside)
	{
		i++;
		int valuehex = 0x0 + i;
		DWORD* BaseModuleAddresses = (DWORD*)(baseinside + valuehex);
	
		//
		//Retrieving information about a range of pages within the virtual address space.
		MEMORY_BASIC_INFORMATION memory_info;
		VirtualQueryEx(curproc,(LPCVOID)BaseModuleAddresses, &memory_info, sizeof(memory_info));

		if (memory_info.Protect & MEMO_PROTEC)
		{
			if (BaseModuleAddresses)
			{
				ReadProcessMemory(curproc, (PVOID)BaseModuleAddresses, &nbuffer, sizeof(BaseModuleAddresses), 0);
				std::cout << szModName << " (" << std::hex << BaseModuleAddresses << ") " << " + " << valuehex << " Acess: " << std::hex << nbuffer << "\n"; // it worked
			}
			else
			{
				std::cout << szModName << " + " << std::hex << BaseModuleAddresses << " NULL" << "\n";
			}
		}
	}
	
	return 0;
}


int main()
{
	//setting jump place
	startpoint:

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

		MODULEINFO mInfoinside = GetModuleInfo(hMods[y]);
		DWORD baseinside = (DWORD)mInfoinside.lpBaseOfDll;
		DWORD sizeinside = (DWORD)mInfoinside.SizeOfImage;
		DWORD entryinside = (DWORD)mInfoinside.EntryPoint;

		//
		// Opening the process with permitions  specified and storing this address into a handle
		HANDLE curproc = OpenProcess(PROCESS_QUERY_INFORMATION |
			PROCESS_VM_READ,
			FALSE, procID); 

		TCHAR szModName[MAX_PATH];
		
		//
		// Get the full path to the module's file.
		GetModuleFileNameEx(curproc, hMods[y], szModName, sizeof(szModName) / sizeof(TCHAR));
		if (baseinside != 0)
		{
			printf(TEXT("\t%s (0x%08X)\t Module number: %d\n"), szModName, hMods[y], module_number);
		}	
	}

	std::cout << "\n insert the module number of the module you want to list: ";
	int modulenumbersearch = 0;

	std::cin >> modulenumbersearch;

	ModuleLister(modulenumbersearch);

	Sleep(4);
	std::cout << "\n" << "Would you like to make another search ? (Y/N) : ";
	std::string decision;
	std::cin >> decision;
	if (decision == "y")
	{
		process = NULL;
		procID = 0;
		hMods[1024] = 0;
		goto startpoint;
	}
	else
	{
		std::cout << "\n";
		return 0;
	}
	std::cout << "\n";
	return 0;
}