#This script tested on cobalt-strike's payload used in blackbyte
#MD5: c84d4ead6c5a2afa9e844806de549dcf

import idautils

def xor_operation_shellcode(data_1,data_2):
    file = open("shellcode.bin","wb")
    i = 0
    k = 0
    decrypted_string = ""
    decrypted_byte_array = b""
    size_1 = (idc.next_head(data_1))-(data_1)
    size_2 = (idc.next_head(data_2))-(data_2)
    bytes_1 = idaapi.get_bytes(data_1,size_1)
    bytes_2 = idaapi.get_bytes(data_2,size_2)
    bytes_2 = bytes_2[:-1]
    for i in range(size_1):
        decrypted_char = bytes_1[i] ^ bytes_2[k]
        value = (hex(decrypted_char)[2:]).zfill(2)
        decrypted_string += (value)
        i = i + 1
        k = k + 1
        if ( k == (len(bytes_2))):
            k = 0
    print("Printing decrypted payload: %s"%(decrypted_string))
    decrypted_byte_array = bytes.fromhex(decrypted_string)
    file.write(decrypted_byte_array)

def encrypted_func(func):
    dism_address = list(idautils.FuncItems(func))
    for address in dism_address:
        generate_disassembly = idc.generate_disasm_line(address,0)
        m = idc.print_insn_mnem(address)
        next_instruction = idc.next_head(address)
        n = idc.print_insn_mnem(next_instruction)
        third_instruction = idc.next_head(next_instruction)
        o = idc.print_insn_mnem(third_instruction)
        if ( m == "lea" and n == "mov" and o == "lea" and idc.get_operand_type(third_instruction,0) == 1 and idc.get_operand_type(third_instruction,1) == 2):
            print("[+]Code Found at %s"%hex(address))
            xor_part_1 = idc.get_operand_value(third_instruction,1)
            xor_part_2 = idc.get_operand_value(address,1)
            xor_operation_shellcode(xor_part_1,xor_part_2)


for func in idautils.Functions():
    name = idc.get_func_name(func)
    encrypted_func(func)
