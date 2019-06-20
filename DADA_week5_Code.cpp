/*************************************************************************
**Author:Kevin Allen
**Date 2/8/2018
** DADA Week 5 homework
**Description:  This progam lists out all running processes, lists the loaded modules for a selected process
and reads memory from a chosen module.  A lot of the code for enumnetaing the process came from the microsoft 
developer pages https://docs.microsoft.com/en-us/windows/desktop/ToolHelp/taking-a-snapshot-and-viewing-processes
****************************************************************************/

#include "stdafx.h"
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>
#include <Psapi.h>
#include <string>



using std::cout;
using std::cin;
using std::endl;

//  Forward declarations:
BOOL GetProcessList();
BOOL ListProcessModules(DWORD dwPID);
BOOL ListProcessThreads(DWORD dwOwnerPID);
void printError(TCHAR* msg);
void displayPages(DWORD pid);
void displayMem(DWORD pid, std::wstring mod);

int main(void)
{
	int userInput = 0;
	
	while (userInput != 6) {
		cout << "Please enter the number of the operation you would like to perform" << endl;
		cout << "1: List all running procesess" << endl;
		cout << "2: List the threads of a specific process" << endl;
		cout << "3: List the modules of a specific process" << endl;
		cout << "4: Get the read/write/execute status of a memory pages of a process" << endl;
		cout << "5: Dump the memory from a process" << endl;
		cout << "6: Quit" << endl;
		cin >> userInput;
		
		while (userInput < 1 || userInput>6) {
			cout << "please enter a valid integer" << endl;
			cin >> userInput;
			
		}
		if (userInput==1) {
			GetProcessList();
		}
		else if (userInput == 2) {
			DWORD targetPID;
			cout << "Please enter the pid of the process." << endl;
			cin >> std::hex >> targetPID;
			ListProcessThreads(targetPID);
		}
		else if (userInput == 3) {
			DWORD targetPID;
			cout << "Please enter the pid of the process." << endl;
			cin >> std::hex >> targetPID;
			ListProcessModules(targetPID);
		}
		else if (userInput == 4) {
			DWORD targetPID;
			cout << "Please enter the pid of the process." << endl;
			cin >> std::hex >> targetPID;
			displayPages(targetPID);
		}
		else if (userInput == 5) {
			DWORD targetPID;
			std::wstring targetMod;
			
			cout << "Please enter the pid of the process." << endl;
			cin >> std::hex >> targetPID;
			cout << "Please enter the name of the module you wish to display, inlcuding extension" << endl;
			std::wcin >> targetMod;
			displayMem(targetPID, targetMod);
		}
	}

	return 0;
}

BOOL GetProcessList()
{
	HANDLE hProcessSnap;
	//HANDLE hProcess;
	PROCESSENTRY32 pe32;
	
	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printError(TEXT("CreateToolhelp32Snapshot (of processes)"));
		return(FALSE);
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		printError(TEXT("Process32First")); // show cause of failure
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return(FALSE);
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do
	{
		_tprintf(TEXT("PROCESS NAME:  %s  Process ID = 0x%08X\n"), pe32.szExeFile, pe32.th32ProcessID);

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return(TRUE);
}


BOOL ListProcessModules(DWORD dwPID)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	// Take a snapshot of all modules in the specified process.
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		printError(TEXT("CreateToolhelp32Snapshot (of modules)"));
		return(FALSE);
	}

	// Set the size of the structure before using it.
	me32.dwSize = sizeof(MODULEENTRY32);

	// Retrieve information about the first module,
	// and exit if unsuccessful
	if (!Module32First(hModuleSnap, &me32))
	{
		printError(TEXT("Module32First"));  // show cause of failure
		CloseHandle(hModuleSnap);           // clean the snapshot object
		return(FALSE);
	}

	// Now walk the module list of the process,
	// and display information about each module
	do
	{
		_tprintf(TEXT("MODULE NAME: %s Base address = 0x%08X Base size = %d\n"), me32.szModule, (DWORD)me32.modBaseAddr, me32.modBaseSize);

	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return(TRUE);
}

BOOL ListProcessThreads(DWORD dwOwnerPID)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		printError(TEXT("Thread32First")); // show cause of failure
		CloseHandle(hThreadSnap);          // clean the snapshot object
		return(FALSE);
	}

	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	do
	{
		if (te32.th32OwnerProcessID == dwOwnerPID)
		{
			_tprintf(TEXT("  THREAD ID      = 0x%08X\n"), te32.th32ThreadID);

		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return(TRUE);
}

void printError(TCHAR* msg)
{
	DWORD eNum;
	TCHAR sysMsg[256];
	TCHAR* p;

	eNum = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, eNum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		sysMsg, 256, NULL);

	// Trim the end of the line and terminate it with a null
	p = sysMsg;
	while ((*p > 31) || (*p == 9))
		++p;
	do { *p-- = 0; } while ((p >= sysMsg) &&
		((*p == '.') || (*p < 33)));

	// Display the message
	_tprintf(TEXT("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg);
}

//function adapted from https://stackoverflow.com/questions/3313581/runtime-process-memory-patching-for-restoring-state/3313700#3313700
void displayPages(DWORD pid) {

	char* p = NULL;
	MEMORY_BASIC_INFORMATION pages;
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);

	for (p = NULL; VirtualQueryEx(process, p, &pages, sizeof(pages)); p += pages.RegionSize) {
		printf("%#10.10x (%6uK)\t", pages.BaseAddress, pages.RegionSize / 1024);
		switch (pages.AllocationProtect) {
		case PAGE_READONLY:
			printf("Read Only\n");
			break;
		case PAGE_READWRITE:
			printf("Read/Write\n");
			break;
		case PAGE_WRITECOPY:
			printf("Copy on Write\n");
			break;
		case PAGE_EXECUTE:
			printf("Execute only\n");
			break;
		case PAGE_EXECUTE_READ:
			printf("Execute/Read\n");
			break;
		case PAGE_EXECUTE_READWRITE:
			printf("Execute/Read/Write\n");
			break;
		case PAGE_EXECUTE_WRITECOPY:
			printf("COW Executable\n");
			break;
		default:
			printf(" ");
		}
	}
}

void displayMem(DWORD pid, std::wstring mod) {
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;
	
	// Take a snapshot of all modules in the specified process.
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		printError(TEXT("CreateToolhelp32Snapshot (of modules)"));
		return;
	}

	// Set the size of the structure before using it.
	me32.dwSize = sizeof(MODULEENTRY32);

	// Retrieve information about the first module,
	// and exit if unsuccessful
	if (!Module32First(hModuleSnap, &me32))
	{
		printError(TEXT("Module32First"));  // show cause of failure
		CloseHandle(hModuleSnap);           // clean the snapshot object
		return;
	}

	// find the chosen module

	while (me32.szModule != mod) {
		Module32Next(hModuleSnap, &me32);
	}

	BYTE* buffer = new BYTE[me32.modBaseSize]; //buffer to store mem dump
	SIZE_T numRead;
	Toolhelp32ReadProcessMemory(pid, me32.modBaseAddr, LPVOID(buffer), me32.modBaseSize, &numRead);

	CloseHandle(hModuleSnap);
	//print out results in hex
	for (int i = 0; i < numRead; i+=16) {
		for (int j = 0; j < 16; j++) {
			printf("%02X ", buffer[i + j]);
		}
		printf("\t");
		//print results in printable characters
		for (int j = 0; j < 16; j++) {
			if (isprint(buffer[i + j])) {
				printf("%c", buffer[i + j]);
			}
			else {
				printf(".");
			}
		}
		printf("\n");
	}

	delete[] buffer;
	
}