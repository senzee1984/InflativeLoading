

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



VOID ParsePe(PBYTE pPE) 
{
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return;
	}

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pPE + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return;
	}

	IMAGE_FILE_HEADER		ImgFileHdr = pImgNtHdrs->FileHeader;

	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
	if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		return;
	}

	printf("[+] Size Of The Image : %x \n", ImgOptHdr.SizeOfImage);
}





int main(int argc, char* argv[]) 
{
	PBYTE	pPE = NULL;
	SIZE_T	sPE = NULL;
	if (!ReadPeFile("C:\\cppsample.exe", &pPE, &sPE)) {
		return -1;
	}
	ParsePe(pPE);
	HeapFree(GetProcessHeap(), NULL, pPE);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(L"C:\\cppsample.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed (%d).\n", GetLastError());
        return 1;
    }
    printf("PID: %lu\n", pi.dwProcessId);
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = NtQueryInformationProcess(pi.hProcess,ProcessBasicInformation,&pbi,sizeof(PROCESS_BASIC_INFORMATION), NULL);

    if (status == 0) {
        printf("PEB Address:%p\n", pbi.PebBaseAddress);
        PVOID imageBaseAddress;
        SIZE_T bytesRead;
        ReadProcessMemory(pi.hProcess, (PCHAR)pbi.PebBaseAddress + sizeof(PVOID) * 2, &imageBaseAddress, sizeof(PVOID), &bytesRead);
        printf("Image Base Address:%p\n",imageBaseAddress);
		BYTE buffer[0x7000];

		if (ReadProcessMemory(pi.hProcess, imageBaseAddress, &buffer, 0x7000, &bytesRead)) {
			printf("Read %llu bytes from Image Base Address\n", bytesRead);
			for (int i = 0; i < bytesRead; i++) {
				if (i % 16 == 0) {
					if (i > 0) {
						printf("  ");
						for (int j = i - 16; j < i; j++) {
							printf("%c", (buffer[j] >= 0x20 && buffer[j] <= 0x7E) ? buffer[j] : '.');
						}
					}
					printf("\n%016llX  ", (UINT64)((PCHAR)imageBaseAddress + i));
				}
				else if (i % 8 == 0) {
					printf("- ");
				}
				printf("%02X ", buffer[i]);
			}

			int bytesInLastLine = bytesRead % 16;
			bytesInLastLine = bytesInLastLine ? bytesInLastLine : 16;
			printf("  ");
			for (int i = bytesRead - bytesInLastLine; i < bytesRead; i++) {
				printf("%c", (buffer[i] >= 0x20 && buffer[i] <= 0x7E) ? buffer[i] : '.');
			}
			printf("\n");
			FILE* file = fopen("dumped.bin", "wb");
			if (file != NULL) {
				fwrite(buffer, 1, bytesRead, file);
				fclose(file);
				printf("Data successfully written to 'dumped.bin'\n");
			}
			else {
				printf("Failed to open 'dumped.bin' for writing\n");
			}
		}
		else {
			printf("Failed to read memory\n");
		}
    }
    else {
        printf("Error");
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

/*
[+] DONE
[+] Size Of The Image : 7000
PID: 28264
PEB Address:0000005E5165F000
Image Base Address:00007FF78E730000
Read 28672 bytes from Image Base Address

00007FF78E730000  4D 5A 90 00 03 00 00 00 - 04 00 00 00 FF FF 00 00   MZ..............
00007FF78E730010  B8 00 00 00 00 00 00 00 - 40 00 00 00 00 00 00 00   ........@.......
00007FF78E730020  00 00 00 00 00 00 00 00 - 00 00 00 00 00 00 00 00   ................
00007FF78E730030  00 00 00 00 00 00 00 00 - 00 00 00 00 00 01 00 00   ................
00007FF78E730040  0E 1F BA 0E 00 B4 09 CD - 21 B8 01 4C CD 21 54 68   ........!..L.!Th
00007FF78E730050  69 73 20 70 72 6F 67 72 - 61 6D 20 63 61 6E 6E 6F   is program canno
00007FF78E730060  74 20 62 65 20 72 75 6E - 20 69 6E 20 44 4F 53 20   t be run in DOS
00007FF78E730070  6D 6F 64 65 2E 0D 0D 0A - 24 00 00 00 00 00 00 00   mode....$.......
......................................................................................
00007FF78E736FE0  00 00 00 00 00 00 00 00 - 00 00 00 00 00 00 00 00   ................
00007FF78E736FF0  00 00 00 00 00 00 00 00 - 00 00 00 00 00 00 00 00   ................
Data successfully written to 'dumped.bin'
*/
