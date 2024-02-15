

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>


#pragma comment(lib, "ntdll.lib")
#pragma warning(disable:4996)

EXTERN_C NTSTATUS NTAPI NtQueryInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);


BOOL ReadPeFile(LPCSTR lpFileName, PBYTE* pPe, SIZE_T* sPe) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;
	PBYTE	pBuff = NULL;
	DWORD	dwFileSize = NULL,
		dwNumberOfBytesRead = NULL;

	hFile = CreateFileA(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == NULL) {
		printf("[!] GetFileSize Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	pBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
	if (pBuff == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	if (!ReadFile(hFile, pBuff, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
		printf("[!] Bytes Read : %d of : %d \n", dwNumberOfBytesRead, dwFileSize);
		goto _EndOfFunction;
	}

	printf("[+] DONE \n");


_EndOfFunction:
	*pPe = (PBYTE)pBuff;
	*sPe = (SIZE_T)dwFileSize;
	if (hFile)
		CloseHandle(hFile);
	if (*pPe == NULL || *sPe == NULL)
		return FALSE;
	return TRUE;
}



DWORD ParsePe(PBYTE pPE)
{
	DWORD size = 0;
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return -1;
	}

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pPE + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return -1;
	}

	IMAGE_FILE_HEADER		ImgFileHdr = pImgNtHdrs->FileHeader;

	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
	if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		return -1;
	}

	printf("[+] Size Of The Image : 0x%x \n", ImgOptHdr.SizeOfImage);
	size = ImgOptHdr.SizeOfImage;
	return size;
}





int main(int argc, char* argv[])
{

	PBYTE	pPE = NULL;
	SIZE_T	sPE = NULL;
	if (argc < 3)
	{
		printf("Usage: ReadPEInMemoryMemory.exe input output\nE.g. ReadPEInMemory.exe calc.exe calc.bin\n");
	    return -1;
    }
	LPCSTR filename = argv[1];
	char* outputbin = argv[2];
	if (!ReadPeFile(filename, &pPE, &sPE)) {
		return -1;
	}

	DWORD size_of_image = ParsePe(pPE);
	HeapFree(GetProcessHeap(), NULL, pPE);

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessA(filename, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		printf("CreateProcess failed (%d).\n", GetLastError());
		return 1;
	}
	printf("Process PID: %lu\n", pi.dwProcessId);
	PROCESS_BASIC_INFORMATION pbi;
	NTSTATUS status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

	if (status == 0) {
		printf("PEB Address:%p\n", pbi.PebBaseAddress);
		PVOID imageBaseAddress;
		SIZE_T bytesRead;

		ReadProcessMemory(pi.hProcess, (PCHAR)pbi.PebBaseAddress + sizeof(PVOID) * 2, &imageBaseAddress, sizeof(PVOID), &bytesRead);
		printf("Image Base Address:%p\n", imageBaseAddress);

		SIZE_T totalSize = size_of_image;	//Total size of PE image in memory
		const SIZE_T CHUNK_SIZE = 0xb000; // Chunk size for reading and writing
		BYTE buffer[0xb000];	//Number of bytes read each time

		
		//SIZE_T bytesRead = 0;
		SIZE_T totalBytesRead = 0;

		// Calculate the number of iterations needed
		int numIterations = (totalSize / CHUNK_SIZE) + (totalSize % CHUNK_SIZE ? 1 : 0);

		FILE* file = fopen(outputbin, "ab"); // Open file in append mode
		if (file == NULL) {
			printf("Failed to open %s for writing\n",outputbin);
			exit(1);
		}

		for (int iteration = 0; iteration < numIterations; iteration++) {
			BYTE buffer[CHUNK_SIZE];
			SIZE_T offset = iteration * CHUNK_SIZE;
			SIZE_T sizeToRead = min(CHUNK_SIZE, totalSize - offset);

			if (!ReadProcessMemory(pi.hProcess, (PBYTE)imageBaseAddress + offset, &buffer, sizeToRead, &bytesRead)) {
				// Handle read error
				printf("Error reading memory: %d\n", GetLastError());
				break;
			}

			fwrite(buffer, 1, bytesRead, file); // Write the chunk to the file
			totalBytesRead += bytesRead;

			// Print each byte (optional, for debugging)
			/*for (int i = 0; i < bytesRead; i++) {
				// ... Your existing printing logic ...
			}*/
		}

		// Clean up
		fclose(file);
		printf("Data successfully written to %s. Total bytes read: 0x%x\n", outputbin,totalBytesRead);
	}
	else {
		printf("Error");
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return 0;
}
