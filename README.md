# InflativeLoading

The tool consists of two components: `ReadPEImMemory.exe` and `InflativeLoading.py`.

## ReadPEInMemory Project

ReadPEInMemory.exe is used to get the in-memory version of the selected PE file. It works by creating a process in suspended state and dumping the main module into a binary file (on your dev machine).

Why? A typical reflective loading process maps each section of a PE file into a newly allocated memory region. Regarding this, I have two concerns: Firstly, although the data of each section is fundamentally consistent whether it resides on disk or in memory, there might still be certain differences for special PE files or under specific circumstances. 

```c
// Code snippet from Maldev course
for (int i = 0; i < pPeHdrs->pImgNtHdrs->FileHeader.NumberOfSections; i++) {
	memcpy(
		(PVOID)(pPeBaseAddress + pPeHdrs->pImgSecHdr[i].VirtualAddress),			// Distination: pPeBaseAddress + RVA
		(PVOID)(pPeHdrs->pFileBuffer + pPeHdrs->pImgSecHdr[i].PointerToRawData),		// Source: pPeHdrs->pFileBuffer + RVA
		pPeHdrs->pImgSecHdr[i].SizeOfRawData							// Size
	);
}
```

Secondly, the content of the PE file already exists in the loader's memory(Like a byte array), but the loader still allocates memory space again. The execution of ReadPEInMemory is completed on the operator's dev machine, the operator gets a dump of the PE file when it is loaded in memory. Although some data still requires updates, there is no need to allocate memory region on the victim's machine.

In this way, rather than manually map a file, we only need to patch specific data region like `Import Directory`, `Base Relocation Table Directory`, `Delayed Load Import Descriptors Directory`, etc.

The dumped main module will be saved as a binary file to append to the shellcode stub.

For instance, ReadPEInMemory executes a classic tool mimikatz and dumps its main module into a binary file.
```shell
PS C:\Users\Administrator\Desktop\petosc\project> .\ReadPEInMemory.exe .\mimikatz.exe mimi.bin
[+] DONE
[+] Size Of The Image : 0x137000
Process PID: 12512
PEB Address:0000000000D41000
Image Base Address:00007FF69AA80000
Data successfully written to mimi.bin. Total bytes read: 0x137000
```

## InflativeLoading Script
The script dynamically generates a shellcode stub and appends it to the dump file. 

The shellcode completes the following tasks:
1. Walk PEB and find kernel32.dll
2. Update command line
3. Parse kernel32.dll to get the address of LoadLibraryA, GetProcAddress function.
4. Locate the prepended dump file with an offset
5. Dynamically fix Import Directory, Base Relocation Table Directory, Delayed Load Import Descriptors Directory, etc.
6. Transfer the execution to the entry point of the PE file.


For instance, use the script to read previously dumped mimikatz and supply proper command line to dump credentials in LSASS:

![image](/screenshot/logonpasswords.jpg)


# Known Issues
1. Supplied command line does not always work properly.
2. Does not work for GUI applications, like mspaint. But calc.exe works well.
3. Does not work for packed applications.

# Improvements In The Future
1. Add a loader for .NET program.
2. Add support for DLL and export functions.
3. Add support for more complex PE files.
4. Improve my shitty code : )

# References
<https://github.com/TheWover/donut>

<https://github.com/d35ha/PE2Shellcode>

<https://github.com/hasherezade/pe_to_shellcode>

<https://github.com/monoxgas/sRDI>

<https://github.com/stephenfewer/ReflectiveDLLInjection>

<https://securityintelligence.com/x-force/defining-cobalt-strike-reflective-loader/>

<https://maldevacademy.com/>
