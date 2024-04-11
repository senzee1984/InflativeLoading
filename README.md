# InflativeLoading
Article: <https://winslow1984.com/books/malware/page/reflectiveloading-and-inflativeloading>

## Major Update History
In this section, major updates are provided. Major updates do include added supports or features.

### 4/11/2024 Added PE Signature Obfuscation
Only a few bytes in the PE header, such as e_lfanew, RVA of Import Directory, are essential for us to complete the loading process. Therefore, other bytes can be overwritten with random ones to hide PE header signatures.

After all the processes are completed, even these bytes will be overwritten for complete obfuscation.

### 4/11/2024 Replace padded NOP with NOP-Like instruction sequences
Before the update, 0x90/NOP instructions are padded after the actual shellcode stub to align a memory page. Many NOPs could be a detection, therefore, InflativeLoading script dynamically selects preset NOP-Like instruction sequences. User can also add new ones or replace existing ones to achieve better obfuscation.

```python
    nop_like_instructions = [
        {"instruction": [0x90], "length": 1},  # NOP
        {"instruction": [0x86, 0xdb], "length": 2},  # xchg bl, bl;
        {"instruction": [0x66, 0x87, 0xf6], "length": 3},  # xchg si, si;
        {"instruction": [0x48, 0x9c, 0x48, 0x93], "length": 4},  # xchg rax, rbx; xchg rbx, rax;
        {"instruction": [0x66, 0x83, 0xc2, 0x00], "length": 4},  # add dx, 0
        {"instruction": [0x48, 0xff, 0xc0, 0x48, 0xff, 0xc8], "length": 6},  # inc rax; dec rax;
        {"instruction": [0x49, 0xf7, 0xd8, 0x49, 0xf7, 0xd8], "length": 6},  # neg r8; neg r8;
        {"instruction": [0x48, 0x83, 0xc0, 0x01, 0x48, 0xff, 0xc8], "length": 7},  # add rax,0x1; dec rax;
        {"instruction": [0x48, 0x83, 0xe9, 0x2, 0x48, 0xff, 0xc1, 0x48, 0xff, 0xc1], "length": 10},  # sub rcx, 2; inc rcx; inc rcx
    ]
```

### 4/11/2024 Improved Shellcode Logic
I added additional shellcode logic to handle some uncommon exceptions. For instance, in the CobaltStrike stateless DLL payload, some base relocation entries are invalid because the page RVA is larger than size of image.

The size of image is 0x58000.
![image](/screenshot/improved-logic1.jpg)

However, some RVA are larger than the number.
![image](/screenshot/improved-logic2.jpg)


### 4/11/2024 Improved PE Dumper
Now the dumper can display more information and provide suggestions for memory allocation:
```shell
// Allocate memory with RX permission for shellcode stub
LPVOID buffer = VirtualAlloc(NULL, 0x1000, 0x3000, 0x20);
// Allocate memory with RW permission for PE Header
VirtualAlloc(buffer + 0x1000, 0x1000, 0x3000, 0x04);
// Allocate memory with RX permission for text section
VirtualAlloc(buffer + 0x2000, 0x1000, 0x3000, 0x20);
// Allocate memory with RW permission for other sections
VirtualAlloc(buffer + 0x2000 + 0x1000, 0x5000, 0x3000, 0x20);
```
The shellcode stub is fixed as 0x1000 bytes, PE header is fixed at 0x1000 bytes, the size of text section and other sections varies.


### 4/11/2024 Added Support For Unmanaged DLL
After the update, unmanaged DLLs can also be converted to PIC shellcode. Test cases for custom DLLs, Havoc stageless DLL payload, and CobaltStrike stageless DLL payload are passed.

### 2/19/2024 Added Basic Support For UPX Packed EXE
I slightly modified the code that fixes IAT, because I found some lines of code are unnecessary. After this, InflativeLoading can execute **some UPX packed EXE programs**, including **calc.exe**, **PsExec**. However, only some of packed programs. Firstly, I will not likely test all possible packing configurations for all tested programs. For the second reason, please continue to read:

For programs that do not have `delayed import directory`, InflativeLoading can execute UPX-packed versions of them. However, unlike unpacked programs, packed programs have all ILT empty.

Take normal calc.exe as an example, ILT and IAT are identical for all modules.
![image](/screenshot/calc_pebear.jpg)

But for the UPX packed calc.exe, ILT is empty for all entries in Import Directory.
![image](/screenshot/packed_calc.jpg)

But if the program has delayed import directory, like Mimikatz, it gets more complex.

For the normal mimikatz.exe, the delayed import directory is as follows:
![image](/screenshot/mimikat_pebear.jpg)

But for the UPX packed mimikatz.exe, PE Bear is unable to parse it, so do I.
![image](/screenshot/packed_mimikatz.jpg)

The below is a passed test case for UPX-packed calc.exe.
![image](/screenshot/packed_calc_test.jpg)


## Background
Converting an exe to shellcode is one of my goals, in this way, some security tools like Mimikatz can be used with more flexibility. Though some tools like **Donut** already achieved it, I still want to create such a tool with my approach, and hopefully, it can bring some improvements.

Motivated and inspired by some classic and modern tools and techniques, InflativeLoading is a tool that can dynamically convert a native EXE to PIC shellcode.

**In short, InflativeLoading generates and prepends a shellcode stub to a dumped PE main module.**

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
PS C:\dev\inflativeloading> .\DumpPEFromMemory.exe .\havocdll.dll havocdll.bin
[+] The file is a DLL file
[+] Image base of mapped .\havocdll.dll is 0x87fd0000
[+] e_lfanew of mapped .\havocdll.dll is 0x80
[+] imageSize of mapped .\havocdll.dll is 0x1e000
[+] Size of optinalHeader of mapped .\havocdll.dll is 0xf0
[+] Offset of section Header of mapped .\havocdll.dll is 0x188
[+] Size of text section of mapped .\havocdll.dll is 0x18000
[+] Size of other sections of mapped .\havocdll.dll is 0x5000

[!] Suggested memory allocations, please adjust accordingly with other memory allocation APIs and languages

// Allocate memory with RX permission for shellcode stub
LPVOID buffer = VirtualAlloc(NULL, 0x1000, 0x3000, 0x20);
// Allocate memory with RW permission for PE Header
VirtualAlloc(buffer + 0x1000, 0x1000, 0x3000, 0x04);
// Allocate memory with RX permission for text section
VirtualAlloc(buffer + 0x2000, 0x18000, 0x3000, 0x20);
// Allocate memory with RW permission for other sections
VirtualAlloc(buffer + 0x2000 + 0x18000, 0x5000, 0x3000, 0x20);

[+] Data successfully written to havocdll.bin
```
![image](/screenshot/dumper-dll-new.jpg)


```shell
PS C:\dev\inflativeloading> .\DumpPEFromMemory.exe .\mimikatz.exe mimikatz.bin
[+] The file is an EXE file
[+] Process PID: 23052
[+] PEB Address:00000000004A5000
[+] Image Base Address:00007FF730E00000
[+] e_lfanew is 0x120
[+] Size Of The Image : 0x137000
[+] Size Of Optional Header : 0xf0
[+] Size Of text Section : 0xc5000
[+] Size of other sections of mapped .\mimikatz.exe is 0x71000

[!] Suggested memory allocations, please adjust accordingly with other memory allocation APIs and languages

// Allocate memory with RX permission for shellcode stub
LPVOID buffer = VirtualAlloc(NULL, 0x1000, 0x3000, 0x20);
// Allocate memory with RW permission for PE Header
VirtualAlloc(buffer + 0x1000, 0x1000, 0x3000, 0x04);
// Allocate memory with RX permission for text section
VirtualAlloc(buffer + 0x2000, 0xc5000, 0x3000, 0x20);
// Allocate memory with RW permission for other sections
VirtualAlloc(buffer + 0x2000 + 0xc5000, 0x71000, 0x3000, 0x20);

[+] 29 iterations are needed

[+] Data successfully written to mimikatz.bin. Total bytes read: 0x137000
```
![image](/screenshot/dumper-exe.jpg)


### InflativeLoading Script
The script dynamically generates a shellcode stub and prepends it to the dump file. 

The shellcode completes the following tasks:
1. Walk PEB and find kernel32.dll
2. Update command line
3. Parse kernel32.dll to get the address of LoadLibraryA, GetProcAddress function.
4. Locate the appended dump file with an offset
5. Dynamically fix Import Directory, Base Relocation Table Directory, Delayed Load Import Descriptors Directory, etc.
6. Transfer the execution to the entry point of the PE file.


For instance, use the script to read previously dumped mimikatz and supply proper command line to dump credentials in LSASS:

![image](/screenshot/logonpasswords.jpg)

Though the shellcode stub should be less than 1000 bytes typically, the script still pads the shellcode stub to **4096 bytes** for alignment with memory page boundary. Then the operator can easily set proper page permission for different memory regions.


## How To Use?
I believe you already went through both components of InflativeLoading, in summary:

1. Use DumpPEFromMemory.exe to select a native EXE and then dump the PE main module from memory into a bin file. For information on selecting EXE files, please refer to the `Best Use Cases` and `Know Issues or Limitations` sections.
2. Use InflativeLoading.py script to prepend a shellcode stub for the dump file. You can choose to provide a command line and whether to execute the generated shellcode immediately. **Currently, the user-supplied command line only works properly for a small set of programs**.


## Best Use Cases
Because InflativeLoading is in its early stage, not every exe is supported well. Unmanaged DLL is supported well; execution of the export function is coming in the next update!

:white_check_mark: Native console program that does not rely on arguments, like stageless C2 implant

:white_check_mark: Native console program with an interactive console/shell, like Mimikatz.

:white_check_mark: Unmanaged DLL

## Improvement Over ReflectiveLoader
:heavy_check_mark: No specific export functions are required, making it more friendly towards PE files for which the source code and compilation are not conveniently accessible

:heavy_check_mark: Avoids unintended results due to differences between the PE file on disk and in memory in certain cases

:heavy_check_mark: Eliminates the need for conversion between the original file offset and RVA

:heavy_check_mark: Avoids additional memory space allocation

:heavy_check_mark: Avoids RWX memory regions.

:heavy_check_mark: Even for RX memory regions, it does not start with the MZ characteristic, increasing the difficulty of investigation.


## Capabilities
:ballot_box_with_check: Support for normal native EXE

:ballot_box_with_check: Support for unmanaged DLL 

:ballot_box_with_check: Support for EXE/DLL that has Delayed Import Directory

:ballot_box_with_check: Fix IAT

:ballot_box_with_check: Fix Base Relocation Directory

:ballot_box_with_check: Tests passed with classic programs like calc, mimikatz, PsExec, etc. 

:ballot_box_with_check: Tests passed with classic C2 payload, such as CobaltStrike and Havoc stageless DLL payload.

:ballot_box_with_check: Partial support packed programs.

## Known Issues or Limitations
:warning: Some of the following issues may be fixed in the future, while some of them remain out of scope due to their nature.

+ Supplied command line does not always work properly. **It is a major area that I will be focusing on**.

+ Does not work for GUI programs, like mspaint.exe. But **calc.exe** works well.

+ Does not work for all packed programs. Some of packed programs can be executed well.

+ Does not work for programs that require other dependencies, like custom DLLs.

+ Only support **x64**, and I do not plan to add support for x86 programs.

If you encounter any of the above issues or limitations, the execution of shellcode may crash, the shellcoded EXE cannot properly identify the command line, or there may be no response.

For instance, PsExec.exe can be converted to PIC shellcode, however, user-supplied command line cannot be identified properly.
```cmd
C:\Users\<...SNIP>\>python InflativeLoading.py -b psexec.bin -c "-s -i powershell" -e true -o psexec_merged.bin

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
| Program | FORMAT | Has GUI? | Supplied Arguments?| Successful Execution | Execute Properly w Arguments |
| ----------- | ----------- | ----------- |----------- | ----------- |----------- | 
| Simple custom C/C++ programs     | EXE |No | No  |:heavy_check_mark: | N/A |
| Simple custom DLL    | DLL |No | No  |:heavy_check_mark: | N/A |
| Common C2 EXE Payload     | EXE |No | No  |:heavy_check_mark: | N/A |
| Common C2 DLL Payload     | DLL |No | No  |:heavy_check_mark: | N/A |
| calc.exe     | EXE | Yes | No |:heavy_check_mark: |N/A |
| mimikatz.exe  | EXE | No | Yes   |:heavy_check_mark: |:heavy_check_mark: |
| PsExec  | EXE | No     |Yes |:heavy_check_mark: |:no_entry_sign:|
| mspaint.exe  | EXE | Yes     |No | :no_entry_sign: |N/A|
| Packed Programs  | EXE | No     |No | Partial|N/A |

Dumped versions of calc.exe and mimikatz.exe can be found in the `bin/` folder of the repository. 


## Improvements In The Future
:bell: The following features and improvements are expected in the future.

+ A separate loader for .NET programS.

+ Add support for DLL export functions.

+ Add support for more packed programs.

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
