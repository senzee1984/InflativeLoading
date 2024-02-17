import ctypes, struct
from keystone import *
import argparse


def print_banner():
    banner="""
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
"""
    print(banner)
    print("Author: Senzee")
    print("Github Repository: https://github.com/senzee1984/InflativeLoading")
    print("Twitter: senzee@1984")
    print("Website: https://senzee.net")
    print("Description: Dynamically convert a native PE to PIC shellcode")
    print("Attention: Bugs are expected, more support and improvements are coming!\n\n\n")


def generate_asm_by_cmdline(new_cmd):
    new_cmd_length = len(new_cmd) * 2 + 12
    unicode_cmd = [ord(c) for c in new_cmd]


    fixed_instructions = [
        "mov rsi, [rax + 0x20];			# RSI = Address of ProcessParameter",
        "add rsi, 0x70; 			# RSI points to CommandLine member",
        f"mov byte ptr [rsi], {new_cmd_length}; # Set Length to the length of new commandline",
        "mov byte ptr [rsi+2], 0xff; # Set the max length of cmdline to 0xff bytes",
        "mov rsi, [rsi+8]; # RSI points to the string",
        "mov dword ptr [rsi], 0x002e0031; 	# Push '.1'",
        "mov dword ptr [rsi+0x4], 0x00780065; 	# Push 'xe'",
        "mov dword ptr [rsi+0x8], 0x00200065; 	# Push ' e'"
    ]

    start_offset = 0xC
    dynamic_instructions = []
    for i, char in enumerate(unicode_cmd):
        hex_char = format(char, '04x')
        offset = start_offset + (i * 2) 
        if i % 2 == 0:
            dword = hex_char
        else:
            dword = hex_char + dword 
            instruction = f"mov dword ptr [rsi+0x{offset-2:x}], 0x{dword};"
            dynamic_instructions.append(instruction)
    if len(unicode_cmd) % 2 != 0:
        instruction = f"mov word ptr [rsi+0x{offset:x}], 0x{dword};"
        dynamic_instructions.append(instruction)
    final_offset = start_offset + len(unicode_cmd) * 2
    dynamic_instructions.append(f"mov byte ptr [rsi+0x{final_offset:x}], 0;")
    instructions = fixed_instructions + dynamic_instructions
    return "\n".join(instructions)


def read_dump_file(file_path):
    with open(file_path, 'rb') as file:
        return bytearray(file.read())

def print_shellcode(sc):
    for i in range(min(20, len(sc))):
        line = sc[i * 20:(i + 1) * 20]
        formatted_line = ''.join([f"\\x{b:02x}" for b in line])
        print(f"buf += b\"{formatted_line}\"")
    print("......"+str(len(sc)-400) +" more bytes......")




if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description='Dynamically generate shellcode stub to append to the dump file')
    parser.add_argument('--bin', '-b', required=True, dest='bin',help='The binary file dumped by DumpPEFromMemory.exe')
    parser.add_argument('--cmdline', '-c', required=False, default="", dest='cmdline',help='Supplied command line')
    parser.add_argument('--output', '-o', required=True, dest='output',help='Save the PIC code as a bin file')
    parser.add_argument('--execution', '-e', required=False, default='False', dest='sc_exec',help='(Only Windows) Immediately execute shellcoded PE? True/False')

    args = parser.parse_args()
    bin= args.bin
    cmdline = args.cmdline
    output = args.output
    sc_exec = args.sc_exec
    pe_array = read_dump_file(bin)

    update_cmdline_asm = generate_asm_by_cmdline(cmdline)	# Generate shellcode that used to update command line


    CODE = (
"start:"
" and rsp, 0xFFFFFFFFFFFFFFF0;"		# Stack alignment
" xor rdx, rdx;"
" mov rax, gs:[rdx+0x60];"		# RAX = PEB Address


"update_cmdline:"
f"{update_cmdline_asm}"


"find_kernel32:"
" mov rsi,[rax+0x18];"			# RSI = Address of _PEB_LDR_DATA
" mov rsi,[rsi + 0x30];"		# RSI = Address of the InInitializationOrderModuleList
" mov r9, [rsi];"			
" mov r9, [r9];"			
" mov r9, [r9+0x10];"			# kernel32.dll
" jmp function_stub;"			# Jump to func call stub


"parse_module:"				# Parsing DLL file in memory
" mov ecx, dword ptr [r9 + 0x3c];"	# R9 = Base address of the module, ECX = NT header offset
" xor r15, r15;"
" mov r15b, 0x88;"			# Offset to Export Directory   
" add r15, r9;"				
" add r15, rcx;"			# R15 points to Export Directory
" mov r15d, dword ptr [r15];"		# R15 = RVA of export directory
" add r15, r9;"				# R15 = VA of export directory
" mov ecx, dword ptr [r15 + 0x18];"	# ECX = # of function names as an index value
" mov r14d, dword ptr [r15 + 0x20];"	# R14 = RVA of ENPT
" add r14, r9;"				# R14 = VA of ENPT


"search_function:"			# Search for a given function
" jrcxz not_found;"			# If RCX = 0, the given function is not found
" dec ecx;"				# Decrease index by 1
" xor rsi, rsi;"
" mov esi, [r14 + rcx*4];"		# RVA of function name
" add rsi, r9;"				# RSI points to function name string


"function_hashing:"			# Hash function name function
" xor rax, rax;"
" xor rdx, rdx;"
" cld;"					# Clear DF flag


"iteration:"				# Iterate over each byte
" lodsb;"				# Copy the next byte of RSI to Al
" test al, al;"				# If reaching the end of the string
" jz compare_hash;"			# Compare hash
" ror edx, 0x0d;"			# Part of hash algorithm
" add edx, eax;"			# Part of hash algorithm
" jmp iteration;"			# Next byte


"compare_hash:"				# Compare hash
" cmp edx, r8d;"			# R8 = Supplied function hash
" jnz search_function;"			# If not equal, search the previous function (index decreases)
" mov r10d, [r15 + 0x24];"		# Ordinal table RVA
" add r10, r9;"				# R10 = Ordinal table VMA
" movzx ecx, word ptr [r10 + 2*rcx];"	# Ordinal value -1
" mov r11d, [r15 + 0x1c];"		# RVA of EAT
" add r11, r9;"				# r11 = VA of EAT
" mov eax, [r11 + 4*rcx];"		# RAX = RVA of the function
" add rax, r9;"				# RAX = VA of the function
" ret;"
"not_found:"
" xor rax, rax;"			# Return zero
" ret;"


"function_stub:"			
" mov rbp, r9;"				# RBP stores base address of Kernel32.dll
" mov r8d, 0xec0e4e8e;"			# LoadLibraryA Hash
" call parse_module;"			# Search LoadLibraryA's address
" mov r12, rax;"			# R12 stores the address of LoadLibraryA function
" mov r8d, 0x7c0dfcaa;"			# GetProcAddress Hash
" call parse_module;"			# Search GetProcAddress's address
" mov r13, rax;"			# R13 stores the address of GetProcAddress function
)


    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(CODE)
    CODE_LEN = len(encoding) + 25     
    CODE_OFFSET = 4096 - CODE_LEN

    CODE2 = (
" jmp fix_import_dir;"			# Jump to fix_import_dir section


"find_nt_header:"			# Quickly return NT header in RAX
" xor rax, rax;"
" mov eax, [rbx+0x3c];"   		# EAX contains e_lfanew
" add rax, rbx;"          		# RAX points to NT Header
" ret;"					


"fix_import_dir:"  			# Init necessary variable for fixing IAT
" xor rsi, rsi;"
" xor rdi, rdi;"
f"lea rbx, [rip+{CODE_OFFSET}];"	# Jump to the dump file
" call find_nt_header;"
" mov esi, [rax+0x90];"  		# ESI = ImportDir RVA
" add rsi, rbx;"         		# RSI points to ImportDir
" mov edi, [rax+0x94];"   		# EDI = ImportDir Size
" add rdi, rsi;"          		# RDI = ImportDir VA + Size


"loop_module:"
" cmp rsi, rdi;"          		# Compare current descriptor with the end of import directory
" je loop_end;"		    		# If equal, exit the loop
" xor rdx ,rdx;"
" mov edx, [rsi];"        		# EDX = ILT RVA (32-bit)
" test rdx, rdx;"         		# Check if ILT RVA is zero (end of descriptors)
" je loop_end;"		    		# If zero, exit the loop
" xor rcx, rcx;"
" mov ecx, [rsi+0xc];"    		# RCX = Module Name RVA
" add rcx, rbx;"          		# RCX points to Module Name
" call r12;"              		# Call LoadLibraryA
" xor rdx ,rdx;"			
" mov edx, [rsi];"        		# Restore ILT RVA
" add rdx, rbx;"          		# RDX points to ILT
" xor r8, r8;"				
" mov r8d, [rsi+0x10];"   		# R8 = IAT RVA	
" add r8, rbx;"           		# R8 points to IAT
" mov rcx, rax;"          		# Module handle for GetProcAddress
" mov r14, rdx;"			# Backup ILT Address
" mov r15, r8;"				# Backup IAT Address


"loop_func:"
" mov rdx, r14;"			# Restore ILT address + processed entries
" mov r8, r15;"				# Restore IAT Address + processed entries
" mov rdx, [rdx];"        		# RDX = Ordinal or RVA of HintName Table
" test rdx, rdx;"         		# Check if it's the end of the ILT/IAT
" je next_module;"	    		# If zero, move to the next descriptor
" mov r9, 0x8000000000000000;"
" test rdx, r9;"  			# Check if it is import by ordinal (highest bit set)
" mov rbp, rcx;"			# Save module base address
" jnz resolve_by_ordinal;"		# If set, resolve by ordinal


"resolve_by_name:"
" add rdx, rbx;"          		# RDX = HintName Table VA
" add rdx, 2;"		  		# RDX points to Function Name
" call r13;"              		# Call GetProcAddress
" jmp update_iat;"        		# Go to update IAT


"resolve_by_ordinal:"
" mov r9, 0x7fffffffffffffff;"
" and rdx, r9;"			   	# RDX = Ordinal number
" call r13;"              		# Call GetProcAddress with ordinal


"update_iat:"
" mov rcx, rbp;"          		# Restore module base address
" mov r8, r15;"				# Restore IAT Address + processed entries
" mov [r8], rax;"         		# Write the resolved address to the IAT
" add r15, 0x8;"             		# Move to the next IAT entry (64-bit addresses)
" add r14, 0x8;"		  	# Movce to the next ILT entry
" jmp loop_func;"			# Repeat for the next function


"next_module:"
" add rsi, 0x14;"         		# Move to next import descriptor
" jmp loop_module;"  			# Continue loop


"loop_end:"




"fix_basereloc_dir:"			# Save RBX //dq rbx+21b0 l46
" xor rsi, rsi;"
" xor rdi, rdi;"
" xor r8, r8;"				# Empty R8 to save page RVA
" xor r9, r9;"				# Empty R9 to place block size
" xor r15, r15;"
" call find_nt_header;"
" mov esi, [rax+0xb0];"  		# ESI = BaseReloc RVA
" add rsi, rbx;"         		# RSI points to BaseReloc
" mov edi, [rax+0xb4];"   		# EDI = BaseReloc Size
" add rdi, rsi;"          		# RDI = BaseReloc VA + Size
" mov r15d, [rax+0x28];"		# R15 = Entry point RVA
" add r15, rbx;"			# R15 = Entry point
" mov r14, [rax+0x30];"			# R14 = Preferred address
" sub r14, rbx;"			# R14 = Delta address 
" mov [rax+0x30], rbx;"			# Update Image Base Address
" mov r8d, [rsi];"			# R8 = First block page RVA
" add r8, rbx;"				# R8 points to first block page (Should add an offset later)
" mov r9d, [rsi+4];"			# First block's size
" xor rax, rax;"
" xor rcx, rcx;"


"loop_block:"
" cmp rsi, rdi;"          		# Compare current block with the end of BaseReloc
" jge basereloc_fixed_end;"    		# If equal, exit the loop
" xor r8, r8;"
" mov r8d, [rsi];"			# R8 = Current block's page RVA
" add r8, rbx;"				# R8 points to current block page (Should add an offset later)
" mov r11, r8;"				# Backup R8
" xor r9, r9;"
" mov r9d, [rsi+4];"			# R9 = Current block size
" add rsi, 8;"				# RSI points to the 1st entry, index for inner loop for all entries
" mov rdx, rsi;"
" add rdx, r9;"
" sub rdx, 8;"				# RDX = End of all entries in current block


"loop_entries:"
" cmp rsi, rdx;"			# If we reached the end of current block
" jz next_block;"			# Move to next block
" xor rax, rax;"
" mov ax, [rsi];"			# RAX = Current entry value
" test rax, rax;"			# If entry value is 0
" jz skip_padding_entry;"		# Reach the end of entry and the last entry is a padding entry
" mov r10, rax;"			# Copy entry value to R10
" and eax, 0xfff;"			# Offset, 12 bits
" add r8, rax;"				# Added an offset


"update_entry:"
" sub [r8], r14;"			# Update the address
" mov r8, r11;"				# Restore r8
" add rsi, 2;"				# Move to next entry by adding 2 bytes
" jmp loop_entries;"


"skip_padding_entry:"			# If the last entry is a padding entry
" add rsi, 2;"				# Directly skip this entry


"next_block:"
" jmp loop_block;"


"basereloc_fixed_end:"
" sub rsp, 0x8;"			# Stack alignment




"fix_delayed_import_dir:"
" call find_nt_header;"
" mov esi, [rax+0xf0];"			# ESI = DelayedImportDir RVA
" test esi, esi;"			# If RVA = 0?
" jz delayed_loop_end;"			# Skip delay import table fix
" add rsi, rbx;"			# RSI points to DelayedImportDir


"delayed_loop_module:"
" xor rcx, rcx;"			
" mov ecx, [rsi+4];"			# RCX = Module name string RVA
" test rcx, rcx;"			# If RVA = 0, then all modules are processed
" jz delayed_loop_end;"			# Exit the module loop
" add rcx, rbx;"			# RCX = Module name
" call r12;"				# Call LoadLibraryA
" mov rcx, rax;"			# Module handle for GetProcAddress for 1st arg
" xor r8, r8;"				
" xor rdx, rdx;"
" mov edx, [rsi+0x10];"			# EDX = INT RVA
" add rdx, rbx;"			# RDX points to INT
" mov r8d, [rsi+0xc];"			# R8 = IAT RVA
" add r8, rbx;"				# R8 points to IAT
" mov r14, rdx;"			# Backup INT Address
" mov r15, r8;"				# Backup IAT Address


"delayed_loop_func:"
" mov rdx, r14;"			# Restore INT Address + processed data
" mov r8, r15;"				# Restore IAT Address + processed data
" mov rdx, [rdx];"			# RDX = Name Address RVA
" test rdx, rdx;"			# If Name Address value is 0, then all functions are fixed
" jz delayed_next_module;"		# Process next module
" mov r9, 0x8000000000000000;"
" test rdx, r9;"			# Check if it is import by ordinal (highest bit set of NameAddress)
" mov rbp, rcx;"			# Save module base address
" jnz delayed_resolve_by_ordinal;"	# If set, resolve by ordinal


"delayed_resolve_by_name:"
" add rdx, rbx;"			# RDX points to NameAddress Table
" add rdx, 2;"				# RDX points to Function Name
" call r13;"				# Call GetProcAddress
" jmp delayed_update_iat;"		# Go to update IAT


"delayed_resolve_by_ordinal:"
" mov r9, 0x7fffffffffffffff;"
" and rdx, r9;"				# RDX = Ordinal number
" call r13;"				# Call GetProcAddress with ordinal


"delayed_update_iat:"
" mov rcx, rbp;"			# Restore module base address
" mov r8, r15;"				# Restore current IAT address + processed
" mov [r8], rax;"			# Write the resolved address to the IAT
" add r15, 0x8;"			# Move to the next IAT entry (64-bit addresses)
" add r14, 0x8;"			# Movce to the next INT entry
" jmp delayed_loop_func;"		# Repeat for the next function


"delayed_next_module:"
" add rsi, 0x20;"			# Move to next delayed imported module
" jmp delayed_loop_module;"		# Continue loop


"delayed_loop_end:"


"all_completed:"        
" call find_nt_header;"
" xor r15, r15;"
" mov r15d, [rax+0x28];"		# R15 = Entry point RVA
" add r15, rbx;"			# R15 = Entry point    		
" jmp r15;"
)

    ks2 = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding2, count2 = ks.asm(CODE2)
    encoding = encoding + encoding2

    sh = b""
    for e in encoding:
        sh += struct.pack("B", e)
    shellcode = bytearray(sh)

    print("[+] Shellcode Stub size: "+str(len(shellcode))+" bytes")
    print("[*] Padded to 0x1000 bytes to align with page boundary")
    merged_shellcode = shellcode + b"\x90"*(0x1000-len(shellcode)) + pe_array
    print("[!] Shellcoded PE's size: "+str(len(merged_shellcode))+" bytes\n\n")
    print_shellcode(merged_shellcode)


    try:
        with open(output, 'wb') as f:
            f.write(merged_shellcode)
            print("\n\nGenerated shellcode successfully saved in file "+output)
    except Exception as e:
        print(e)
	

    if sc_exec.lower() == "true": 
        ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
        ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(merged_shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))
        buf = (ctypes.c_char * len(merged_shellcode)).from_buffer(merged_shellcode)
        ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(ptr), buf, ctypes.c_int(len(merged_shellcode)))
        print("\n\n[#] Shellcode located at address %s" % hex(ptr))
        input("\n[!] PRESS TO EXECUTE SHELLCODED EXE...")
        ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0), ctypes.c_int(0), ctypes.c_uint64(ptr), ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))
