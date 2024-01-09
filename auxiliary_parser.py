import struct

def read_pe_file(file_path):
    with open(file_path, 'rb') as file:
        return bytearray(file.read())

def parse_pe_data(byte_array, offset, size):
    data_bytes = byte_array[offset:offset + size]
    return int.from_bytes(data_bytes, byteorder='little')

def read_string_from_offset(byte_array, offset):
    end = offset
    while end < len(byte_array) and byte_array[end] != 0x00:
        end += 1
    byte_string = byte_array[offset:end]
    return byte_string
    return byte_string.decode('utf-8', errors='ignore')

pe_file_path = 'dumped1.bin'
byte_array = read_pe_file(pe_file_path)


e_lfanew = parse_pe_data(byte_array, 0x3c, 4)
print(f"e_lfanew: {e_lfanew:#x}")

image_base = parse_pe_data(byte_array, e_lfanew + 0x30, 8)
print(f"ImageBase: {image_base:#x}")

importdir_rva = parse_pe_data(byte_array, e_lfanew + 0x90, 4)
print(f"Import RVA: {importdir_rva:#x}")

importdir_size = parse_pe_data(byte_array, e_lfanew + 0x94, 4)
print(f"Import Size: {importdir_size:#x}")

basereloc_rva = parse_pe_data(byte_array, e_lfanew + 0xb0, 4)
print(f"Basereloc RVA: {basereloc_rva:#x}")

basereloc_size = parse_pe_data(byte_array, e_lfanew + 0xb4, 4)
print(f"Basereloc size: {basereloc_size:#x}")


end_of_importdir = importdir_rva+ importdir_size
i = importdir_rva

while i < end_of_importdir:
    ILT_rva = parse_pe_data(byte_array, i, 4)
    IAT_rva = parse_pe_data(byte_array, i+0x10, 4)
    if ILT_rva == 0 or IAT_rva ==0:
        break
    module_name_rva = parse_pe_data(byte_array, i+0xc, 4)
    modulename_bytes = read_string_from_offset(byte_array, module_name_rva)
    print(f"\n\nModule: {modulename_bytes.decode('utf-8', errors='ignore')}")  
    print(f"ILT RVA: {ILT_rva:#x} IAT RVA: {IAT_rva:#x}")
    processed = 0

    while True:
        ILT_Entry = ILT_rva + processed
        IAT_Entry = IAT_rva + processed
        if ILT_Entry == 0:
            break
        ILT_Data = parse_pe_data(byte_array, ILT_Entry, 8)
        IAT_Data = parse_pe_data(byte_array, IAT_Entry, 8)
        if ILT_Data == 0:
            break
        print(f"---- ILT_Data: {ILT_Data:#x} IAT_Data: {IAT_Data:#x}")
        processed = processed + 0x8
    i = i + 0x14
