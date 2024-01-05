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
		IAT_THUNK = Func_Addr
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
" mov eax, [rbx+0x3c];"		# eax contains e_lfanew
" mov r11, [eax+0x90];"		# r11 contains ImportDir RVA
" add r11, rbx;"		# r11 points to ImportDir
" mov r14, [eax+0xb0];"		# r14 contains BaseRelocDir RVA
" add r14, rbx;"		# r14 points to BaseRelocDir



'''
