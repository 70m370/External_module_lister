#include<Windows.h>
#include<psapi.h>
#include<TlHelp32.h>
#include<iostream>
#include<string>

//
//Project IDEA so far

// - CHECK 1
//receive user input(executable name) - search for it - find the process ID

// - CHECK 2
//run the printmodules, list the modules inside the application

// - DO
//ask for the specified module name to list what its loading in memory

//
//create a static menu where you restart the search, Getasynckeystate - something to restart the app

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

uintptr_t GetModuleBaseAddress(DWORD procId, char* modName) // uintptr_t architecture independet variable - usable in any architechure - will run in x86 x64
{//module base address is going to be the function that acces the memory variables insite the procID
	uintptr_t modBaseAddr = 0; //unsigned int pointer
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId); //TH32CS_SNAPMODULE includes all modules of the process specified in th32ProcessID in the snapshot. 
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry; //MODULEENTRY32 Describes an entry from a list of the modules belonging to the specified process.
		modEntry.dwSize = sizeof(modEntry);// using the size refference to module
		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				if (!strcmp(modEntry.szExePath, modName))//.szModule = module name
				{
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr; //The base address of the module in the context of the owning process.
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
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
//the problem is inside here, something with the virtualquery- found the problem - 
int ModuleLister(int module_number_input)
{
	MODULEINFO mInfoinside = GetModuleInfo(hMods[module_number_input]);
	DWORD baseinside = (DWORD)mInfoinside.lpBaseOfDll;
	DWORD sizeinside = (DWORD)mInfoinside.SizeOfImage;
	DWORD entryinside = (DWORD)mInfoinside.EntryPoint;

	int i = 0;

	HANDLE curproc = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, procID); //used to be FALSE - testing right now

	TCHAR szModName[MAX_PATH];
	DWORD nbuffer;
	//
	// Get the full path to the module's file.
	GetModuleFileNameEx(curproc, hMods[module_number_input], szModName, sizeof(szModName) / sizeof(TCHAR));
	//moduleBase = GetModuleBaseAddress(procId, L"ac_client.exe");

	while (i <= sizeinside)
	{
		int num = 400000;
		i++;
		int valuehex = 0x0 + i;
		DWORD* BaseModuleAddresses = (DWORD*)(hMods[module_number_input] + valuehex);
		//unsigned long long* BaseModuleAddresses = (unsigned long long*)(ac_module + valuehex);
		DWORD oldprotect;
		VirtualProtectEx(process, (PVOID)BaseModuleAddresses,sizeof(BaseModuleAddresses), PAGE_EXECUTE_READ,&oldprotect);
		ReadProcessMemory(process, (PVOID)BaseModuleAddresses, &nbuffer, sizeof(BaseModuleAddresses), 0);
		
		//
		//Retrieving information about a range of pages within the virtual address space.
		MEMORY_BASIC_INFORMATION memory_info;
		VirtualQuery((LPCVOID)BaseModuleAddresses, &memory_info, sizeof(memory_info));
		//
		//the problem is the exported file - its not receiving all the info gathered
		//
		//Checking if the memory region inside the page is free
		//if (memory_info.State & MEM_FREE)
		//{
		//	printf("ERROR CODE 0x%08x", GetLastError());
		//	break;
		//}
		//
		//Checking the page permission to proceed
		if (memory_info.Protect & MEMO_PROTEC)
		{
			DWORD* BaseModuleAddressesValues = (DWORD*)(*BaseModuleAddresses);
			//
			//checking if the Addresses != NULL
			if (BaseModuleAddressesValues)
			{
				//
				//exporting dump content to inside File
				//textdump << szModName << " + " << std::hex << BaseModuleAddresses << " Acess: " << std::hex << BaseModuleAddressesValues << "\n";
				//fprintf(fptr, "%s  +  %x  Access:  %x \t%d\n",szModName,BaseModuleAddresses,BaseModuleAddressesValues,simple_counter);
				std::cout << szModName << " + " << std::hex << BaseModuleAddresses << " Acess: " << std::hex << BaseModuleAddressesValues << "\n";
				//modules_i_can_read++;
			}
		}
		VirtualProtectEx(process, (PVOID)BaseModuleAddresses, sizeof(BaseModuleAddresses), oldprotect, &oldprotect);
	}

	return 0;
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
	//DWORD ModulesAddreessess[MAX_PATH];
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
			FALSE, procID); //used to be FALSE - testing right now

		TCHAR szModName[MAX_PATH];
		
		//
		// Get the full path to the module's file.
		GetModuleFileNameEx(curproc, hMods[y], szModName, sizeof(szModName) / sizeof(TCHAR));
		//ModulesAddreessess[y] = GetModuleBaseAddress(procID, (char*)(szModName[y]));
		//
		//printing modules path inside application and their size.          
		printf(TEXT("\t%s (0x%08X)\t Module number: %d\n"), szModName, hMods[y], module_number);
		
		
	}

	int modulenumbersearch = 0;

	std::cin >> modulenumbersearch;

	ModuleLister(modulenumbersearch);//problem inside here finding the correct place in memory where the module is stored

	Sleep(4);
	//const wchar_t* szName = name.c_str();
	//printf("%c", procname);
	std::cout << "\n";
	//GetProcId(finalexecname);
	//PrintModules();
	int test = 0;
	std::cin >> test;
	// free((void*)finalexecname);
	return 0;
}

//	Idea to solve this problem, export the listing functions to a dll to execute it inside, inject the dll and then use the dll functions through the Loadlibraryex

//	07/11 - I tried to use readprocessmemory, dont got any luck - changed the memory protection nothing - new function - check Github to see the changes 