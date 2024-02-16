# InflativeLoading

## Background
Converting an exe to shellcode for flexibility was one of my goals, though some tools like **Donut** already achieved it, I still want to create such a tool with my approach, and hopefully, it can bring some improvements.

Motivated and inspired by some classic and modern tools and techniques, InflativeLoading is a tool that can dynamically convert a native EXE to PIC shellcode.

The tool consists of two components: `DumpPEFromMemory.exe` and `InflativeLoading.py`.

## Included Tools

### DumpPEFromMemory Project

DumpPEFromMemory.exe is used to get the in-memory version of the selected PE file. It works by creating a process in suspended state and dumping the main module into a binary file (on your dev machine).

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

Secondly, the content of the PE file already exists in the loader's memory(Like a byte array), but the loader still allocates memory space again. The execution of DumpPEFromMemory is completed on the operator's dev machine, the operator gets a dump of the PE file when it is loaded in memory. Although some data still requires updates, there is no need to allocate memory region on the victim's machine.

In this way, rather than manually map a file, we only need to patch specific data regions like `Import Directory`, `Base Relocation Table Directory`, `Delayed Load Import Descriptors Directory`, etc.

The dumped main module will be saved as a binary file to append to the shellcode stub.

For instance, DumpPEFromMemory executes a classic tool mimikatz, and dumps its main module into a binary file.
```shell
PS C:\Users\Administrator\Desktop\petosc\project> .\DumpPEFromMemory.exe .\mimikatz.exe mimi.bin
[+] DONE
[+] Size Of The Image : 0x137000
Process PID: 12512
PEB Address:0000000000D41000
Image Base Address:00007FF69AA80000
Data successfully written to mimi.bin. Total bytes read: 0x137000
```

### InflativeLoading Script
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

Though the shellcode stub should be less than 1000 bytes typically, the script still pads the shellcode stub to **4096 bytes** for alignment with memory page boundary. Then the operator can easily set proper page permission for different memory regions.


## Capabilities
:heavy_check_mark: Support for normal native EXE

:heavy_check_mark: Support for Delayed Import Directory

:heavy_check_mark: Fix IAT

:heavy_check_mark: Fix Base Relocation Directory

:heavy_check_mark: Tests passed with classic programs like calc, mimikatz, PsExec, etc. 

## Known Issues
:confused: Supplied command line does not always work properly.

:pensive: Does not work for GUI applications, like mspaint. But **calc.exe** works well.

:no_entry_sign: Does not work for packed applications.

:warning: Only support **x64**, and I do not plan to add support for x86 programs.

## Improvements In The Future
:bell: Add a loader for .NET program.

:smirk: Add support for DLL and export functions.

:relaxed:Add support for more complex PE files.

:flushed: Improve existing shitty code : )

## Acknowledgements and References
The following resources inspired me a lot during my research and development:

<https://github.com/TheWover/donut>

<https://github.com/d35ha/PE2Shellcode>

<https://github.com/hasherezade/pe_to_shellcode>

<https://github.com/monoxgas/sRDI>

<https://github.com/stephenfewer/ReflectiveDLLInjection>

<https://securityintelligence.com/x-force/defining-cobalt-strike-reflective-loader/>

<https://maldevacademy.com/>
