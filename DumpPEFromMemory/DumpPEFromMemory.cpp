#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <cstdint>
#include <ctype.h>

#pragma comment(lib, "ntdll.lib")
#pragma warning(disable:4996)

EXTERN_C NTSTATUS NTAPI NtQueryInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);

BOOL MemoryAllocationSuggestion(DWORD textSize, DWORD otherSectionSize)
{
	printf("\n[!] Suggested memory allocations, please adjust accordingly with other memory allocation APIs and languages\n\n");
	printf("// Allocate memory with RX permission for shellcode stub\n");
	printf("LPVOID buffer = VirtualAlloc(NULL, 0x1000, 0x3000, 0x20);\n");
	printf("// Allocate memory with RW permission for PE Header\n");
	printf("VirtualAlloc(buffer + 0x1000, 0x1000, 0x3000, 0x04);\n");
	printf("// Allocate memory with RX permission for text section\n");
	printf("VirtualAlloc(buffer + 0x2000, 0x%x, 0x3000, 0x20);\n", textSize);
	printf("// Allocate memory with RW permission for other sections\n");
	printf("VirtualAlloc(buffer + 0x2000 + 0x%x, 0x%x, 0x3000, 0x20);\n", textSize, otherSectionSize);
	return TRUE;
}


BOOL DumpPEFromMemory(LPCSTR filename, char* outputbin)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessA(filename, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		printf("[!] CreateProcess failed (%d).\n", GetLastError());
		return FALSE;
	}
	printf("[+] Process PID: %lu\n", pi.dwProcessId);
	PROCESS_BASIC_INFORMATION pbi;
	NTSTATUS status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

	if (status == 0) 
	{
		printf("[+] PEB Address:%p\n", pbi.PebBaseAddress);
		
		PVOID imageBaseAddress;
		SIZE_T bytesRead;
		ReadProcessMemory(pi.hProcess, (PCHAR)pbi.PebBaseAddress + sizeof(PVOID) * 2, &imageBaseAddress, sizeof(PVOID), &bytesRead);
		printf("[+] Image Base Address:%p\n", imageBaseAddress);

		DWORD e_lfanew;
		ReadProcessMemory(pi.hProcess, (PBYTE)imageBaseAddress+0x3c, &e_lfanew, sizeof(e_lfanew), &bytesRead);
		printf("[+] e_lfanew is 0x%x\n", e_lfanew);


		DWORD imageSize_offset = e_lfanew + 0x50;
		DWORD imageSize = 0;
		ReadProcessMemory(pi.hProcess, (PBYTE)imageBaseAddress+imageSize_offset, &imageSize, sizeof(imageSize), &bytesRead);
		printf("[+] Size Of The Image : 0x%x \n", imageSize);

		DWORD offset_optionalHeaderSize = e_lfanew + 0x14;
		WORD optionalHeaderSize;
		ReadProcessMemory(pi.hProcess, (PBYTE)imageBaseAddress + offset_optionalHeaderSize, &optionalHeaderSize, sizeof(optionalHeaderSize), &bytesRead);
		printf("[+] Size Of Optional Header : 0x%x \n", optionalHeaderSize);

		DWORD offset_sectionHeader = e_lfanew + 0x18 + optionalHeaderSize;
		DWORD textSize;
		ReadProcessMemory(pi.hProcess, (PBYTE)imageBaseAddress + offset_sectionHeader + 0x8, &textSize, sizeof(textSize), &bytesRead);
		textSize = (textSize + 0x0FFF) & ~0x0FFF;
		printf("[+] Size Of text Section : 0x%x \n", textSize);

		DWORD otherSectionSize = imageSize - textSize - 0x1000;
		otherSectionSize = (otherSectionSize + 0x0FFF) & ~0x0FFF;
		printf("[+] Size of other sections of mapped %s is 0x%x\n", filename, otherSectionSize);
		MemoryAllocationSuggestion(textSize, otherSectionSize);

		SIZE_T size_of_image = imageSize;
		const SIZE_T CHUNK_SIZE = 0xb000; // Chunk size for reading and writing
		BYTE buffer[0xb000];	//Number of bytes read each time
		SIZE_T totalBytesRead = 0;


		// Calculate the number of iterations needed
		int numIterations = (size_of_image / CHUNK_SIZE) + (size_of_image % CHUNK_SIZE ? 1 : 0);
		printf("\n[+] %d iterations are needed\n", numIterations);
		
		FILE* file = fopen(outputbin, "ab"); // Open file in append mode
		if (file == NULL) 
		{
			printf("[!] Failed to open %s for writing\n", outputbin);
			exit(1);
		}

		for (int iteration = 0; iteration < numIterations; iteration++) 
		{
			BYTE buffer[CHUNK_SIZE];
			SIZE_T offset = iteration * CHUNK_SIZE;
			SIZE_T sizeToRead = min(CHUNK_SIZE, size_of_image - offset);

			if (!ReadProcessMemory(pi.hProcess, (PBYTE)imageBaseAddress + offset, &buffer, sizeToRead, &bytesRead)) 
			{
				printf("[!] Error reading memory: %d\n", GetLastError());
				break;
			}

			fwrite(buffer, 1, bytesRead, file);
			totalBytesRead += bytesRead;
		}

		fclose(file);
		printf("\n[+] Data successfully written to %s. Total bytes read: 0x%x\n", outputbin, totalBytesRead);

	    TerminateProcess(pi.hProcess, 0);
		return TRUE;
	}
	else
	{
		printf("[!] Query failed\n");
		return FALSE;
	}
}

BOOL InflateFromDisk(LPCSTR filename, char* outputbin)
{
	HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	HANDLE hSection = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, NULL, NULL, NULL);
	if (hSection == NULL) {
		printf("[!] CreateFileMappingA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	PBYTE PeBase = (PBYTE)MapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
	if (PeBase == NULL) {
		printf("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	DWORD e_lfanew = *((DWORD*)((BYTE*)PeBase + 0x3c));
	DWORD imageSize = *((DWORD*)((BYTE*)PeBase + e_lfanew + 0x50));

	DWORD offset_optionalHeaderSize = e_lfanew + 0x14;
	WORD optionalHeaderSize = *((WORD*)((BYTE*)PeBase + offset_optionalHeaderSize));
	DWORD offset_sectionHeader = e_lfanew + 0x18 + optionalHeaderSize;
	DWORD textSize = *((DWORD*)((BYTE*)PeBase + offset_sectionHeader + 0x8));
	textSize = (textSize + 0x0FFF) & ~0x0FFF;
	DWORD otherSectionSize = imageSize - textSize - 0x1000;
	otherSectionSize = (otherSectionSize + 0x0FFF) & ~0x0FFF;

	printf("[+] Image base of mapped %s is 0x%x\n", filename, PeBase);
	printf("[+] e_lfanew of mapped %s is 0x%x\n", filename, e_lfanew);
	printf("[+] imageSize of mapped %s is 0x%x\n", filename, imageSize);

	printf("[+] Size of optinalHeader of mapped %s is 0x%x\n", filename, optionalHeaderSize);
	printf("[+] Offset of section Header of mapped %s is 0x%x\n", filename, offset_sectionHeader);
	printf("[+] Size of text section of mapped %s is 0x%x\n", filename, textSize);
	printf("[+] Size of other sections of mapped %s is 0x%x\n", filename, otherSectionSize);

	MemoryAllocationSuggestion(textSize, otherSectionSize);

	FILE* file = fopen(outputbin, "wb"); 
	if (file == NULL)
	{
		printf("[!] Failed to open %s for writing\n", outputbin);
		exit(1);
	}
	fwrite(PeBase, 1, imageSize, file);
	fclose(file);
	printf("\n[+] Data successfully written to %s\n", outputbin);
	CloseHandle(hFile);
	CloseHandle(hSection);
	return TRUE;
}



int main(int argc, char* argv[])
{
	PBYTE	pPE = NULL;
	SIZE_T	sPE = NULL;
	if (argc < 3)
	{
		printf("[!] Usage: DumpPEFromMemoryMemory.exe <Native EXE/DLL> <Dump File> \nE.g. ReadPEInMemory.exe mimikatz.exe mimikatz.bin\n");
		return -1;
	}
	LPCSTR filename = argv[1];
	char* outputbin = argv[2];


	char extension[4] = { 0 };
	if (strlen(filename) > 4)	//End with .exe or .dll
	{
		for (int i = 0; i < 3; i++) 
		{
			extension[i] = tolower(filename[strlen(filename) - 3 + i]);
		}
	}
	else
	{
		printf("[!] Invalid file extension\n");
		return -1;
	}

	if (strcmp(extension, "exe") == 0)
	{
		printf("[+] The file is an EXE file\n");
		DumpPEFromMemory(filename, outputbin);
	}
	else if(strcmp(extension, "dll") == 0)
	{
		printf("[+] The file is a DLL file\n");
		InflateFromDisk(filename, outputbin);
	}
	else
	{
		printf("[!] Invalid PE file\n");
		return -1;
	}

	return 0;
}
