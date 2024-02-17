# InflativeLoading

## Background
Converting an exe to shellcode is one of my goals, in this way, some security tools like Mimikatz can be used with more flexibility. Though some tools like **Donut** already achieved it, I still want to create such a tool with my approach, and hopefully, it can bring some improvements.

Motivated and inspired by some classic and modern tools and techniques, InflativeLoading is a tool that can dynamically convert a native EXE to PIC shellcode.

**In short, InflativeLoading generates and appends a shellcode stub to a dumped PE main module.**

The tool consists of two components: `DumpPEFromMemory.exe` and `InflativeLoading.py`.

## Included Components
To convert a native EXE to shellcode, the following 2 components are required.

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


## How To Use?
I believe you already went through both components of InflativeLoading, in summary:

1. Use DumpPEFromMemory.exe to select a native EXE, and then dump the PE main module from memory into a bin file. Regarding the selection of EXE files, please refer to `Best Use Cases` and `Know Issues or Limitations` section.
2. Use InflativeLoading.py script to append a shellcode stub for the dump file. You can choose to provide command line and whether to execute generated shellcode immediately. **Currently, user-supplied command line only works properly for a small set of programs**.


## Best Use Cases
Because InflativeLoading is in its early stage, not every exe is supported well.

:white_check_mark: Native console program that does not rely on arguments, like custom C programs

:white_check_mark: Native console program that has an interactive console/shell, like Mimikatz.


## Capabilities

:ballot_box_with_check: Support for normal native EXE

:ballot_box_with_check: Support for EXE that has Delayed Import Directory

:ballot_box_with_check: Fix IAT

:ballot_box_with_check: Fix Base Relocation Directory

:ballot_box_with_check: Tests passed with classic programs like calc, mimikatz, PsExec, etc. 

## Known Issues or Limitations
:warning: Some of following issues may be fixed in the future, while some of them remain out of scope due to the nature.

+ Supplied command line does not always work properly. **It is a major area that I will be focusing on**.

+ Does not work for GUI programs, like mspaint.exe. But **calc.exe** works well.

+ Does not work for packed programs.

+ Does not work for programs that require other dependencies, like custom DLLs.

+ Only support **x64**, and I do not plan to add support for x86 programs.

If you encounter any of the above issues or limitations, the execution of shellcode may crash, or the shellcoded EXE cannot properly identify the command line, or no response.

For instance, PsExec.exe can be converted to PIC shellcode, however, user-supplied command line cannot be identified properly.
```cmd
C:\Users\Administrator\Desktop\VTF\poc\peshellcodify>python InflativeLoading.py -b psexec.bin -c "-s -i powershell" -e true -o psexec_merged.bin

<...SNIP...>

Generated shellcode successfully saved in file psexec_merged.bin

[#] Shellcode located at address 0x27159360000

[!] PRESS TO EXECUTE SHELLCODED EXE...

Python Console v3.12.2 - Python
Copyright  2001-2023 Python Software Foundation. Copyright  2000 BeOpen.com. Copyright  1995-2001 CNRI. Copyright  1991-1995 SMC.
Python Software Foundation

Couldn't install PSEXESVC service:
The specified resource type cannot be found in the image file.
```

## Test Cases
| Program | Has GUI? | Supplied Arguments?| Successful Execution | Execute Properly w Arguments |
| ----------- | ----------- |----------- | ----------- |----------- | 
| Simple custom C/C++ program     | No | No  |:heavy_check_mark: | N/A |
| calc.exe     | No | No |:heavy_check_mark: |N/A |
| mimikatz.exe  | No | Yes   |:heavy_check_mark: |:heavy_check_mark: |
| PsExec  | No     |Yes |:heavy_check_mark: |:no_entry_sign:|
| mspaint.exe  | No     |No | :no_entry_sign: |N/A|
| Packed Programs  | No     |No | :no_entry_sign: |:no_entry_sign:|

Dumped versions of calc.exe and mimikatz.exe can be found in the `bin/` folder of the repository. 


## Improvements In The Future
:bell: The following features and improvements are expected in the future.

+ A separate loader for .NET program.

+ Add support for DLL and export functions.

+ Add support for more complex PE files, like packed programs.

+ Improve the shitty code : )

## Acknowledgements and References
The following resources inspired me a lot during my research and development:

<https://github.com/TheWover/donut>

<https://github.com/d35ha/PE2Shellcode>

<https://github.com/hasherezade/pe_to_shellcode>

<https://github.com/monoxgas/sRDI>

<https://github.com/stephenfewer/ReflectiveDLLInjection>

<https://securityintelligence.com/x-force/defining-cobalt-strike-reflective-loader/>

<https://maldevacademy.com/>
