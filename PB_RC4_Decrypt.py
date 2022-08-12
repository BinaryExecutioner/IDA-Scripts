import idautils
import idaapi
import binascii
import base64
from arc4 import ARC4

def rc4_decrypt(key,data):
    arc4 = ARC4(key)
    decrypt_string = arc4.decrypt(data)
    print(decrypt_string)
    

def swap32(x):
    return (((x << 24) & 0xFF000000) |
            ((x <<  8) & 0x00FF0000) |
            ((x >>  8) & 0x0000FF00) |
            ((x >> 24) & 0x000000FF))

def encrypted_func(func):
    dism_address = list(idautils.FuncItems(func))
    for address in dism_address:
        generate_disassembly = idc.generate_disasm_line(address,0)
        m = idc.print_insn_mnem(address)
        next_instruction = idc.next_head(address)
        n = idc.print_insn_mnem(next_instruction)
        third_instruction = idc.next_head(next_instruction)
        o = idc.print_insn_mnem(third_instruction)
        fourth_instruction = idc.next_head(third_instruction)
        fifth_instruction = idc.next_head(fourth_instruction)
        if (m == "push" and n == "push" and o == "push" and idc.get_operand_value(address,0) == 1 and idc.get_operand_type(next_instruction,0) == 5 and idc.get_operand_type(third_instruction,0) == 5 ):
            x = idc.get_operand_value(fifth_instruction,1)
            length = idc.get_operand_value(third_instruction,0)
            k = idc.get_operand_value(next_instruction,0)
            key = swap32(k)
            data_bytes = idc.get_bytes(x,length)
            key_1 = str(hex(key))
            key_bytes = bytes.fromhex(key_1[2:])
            rc4_decrypt(key_bytes,data_bytes)
        

func = here()    
encrypted_func(func)
