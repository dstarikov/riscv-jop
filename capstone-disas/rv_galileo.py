#!/usr/bin/env python3

# usage: ./... <file name> <offset> <size> (optional: <search token>)
# This was written using capstone's next branch, commit 2f38802

from capstone import *
from capstone.riscv import *
import sys
import re
import math


jmp_instr_pattern = re.compile(r"(c\.)?j(al)?(r)?")
jmpi_instr_pattern = re.compile(r"(c\.)?j(al)?r")
hex_pattern = re.compile(r"(?:-)?(?:0x)?[0-9a-f]+$")
arch = CS_ARCH_RISCV
mode = CS_MODE_RISCV64 | CS_MODE_RISCVC
md = Cs(arch, mode)
md.detail = True
code = None


def extract_hex(op_str):
    h = hex_pattern.search(op_str)
    if h is None:
        print(op_str)
        print(len(op_str))
#    print(h.group())
    return int(h.group(), 0)


def is_indirect_jmp(instr_mnem):
    return jmpi_instr_pattern.match(instr_mnem)


def handle_indirect_jmp(addr):
    for i in range(1, 5):
        instr_seq = md.disasm(code[addr:], addr, i)
        out = print_instr_seq(instr_seq, addr+(4*(i+1)))
        if out is not None:
            return out


def print_instr_seq(instr_seq, end_addr):
    out = ""
    last_instr = None
    for instr in instr_seq:
        out += "0x{:x}:\t".format(instr.address)
        out += "{}\t".format(bytes(instr.bytes).hex()) if instr.size == 4 else "{}    \t".format(bytes(instr.bytes).hex())
        out += "\t{}\t{}\t({} bytes)\n".format(instr.mnemonic, instr.op_str, instr.size)
        last_instr = instr
        # did we interpret past then actual jmp?
        if instr.address > end_addr:
            return

    if last_instr is None:
        return
    
    last_mnem = last_instr.mnemonic
    # do we still have a jmp at the end?
    if last_mnem is not None and jmp_instr_pattern.match(last_mnem):
        if not is_indirect_jmp(last_mnem):
            imm = extract_hex(last_instr.op_str)
            #print("relative jump!: {:x}".format(imm))
            rel_jmp = handle_indirect_jmp(last_instr.address + imm)
            if rel_jmp:
                out += rel_jmp

        return out


def telescope(idx, init_size, reg):
    # riscv64gc allows for 16-bit and 32-bit instructions
    # this must be an even number
    max_size = 8
    max_offset = max_size - init_size

    for offset in range(0, max_offset+1, 2):
        start = idx - offset
        size = init_size + offset
        # a sequence can have any combination of 2-byte and 4-byte instructions
        for instr_count in range(int(math.ceil(size/4.0)), int((size/2)+1)):
            instr_seq = md.disasm(code[start:], start, instr_count)
            gadget = print_instr_seq(instr_seq, idx)
            if gadget is not None and (reg is None or reg in gadget):
                print(gadget)


def main():
    file_name = sys.argv[1]
    offset = int(sys.argv[2], 0)
    size = int(sys.argv[3], 0)
    reg = None
    if len(sys.argv) > 4:
        reg = sys.argv[4]

    global code
    with open(file_name, mode="rb") as file:
        code = file.read()

    idx = offset
    upper_bound = idx + size

    instr_seq = md.disasm(code[idx:], idx, 1)
    while idx < upper_bound:
        for instr in instr_seq:
            # are we looking at a jmp?
            if jmp_instr_pattern.match(instr.mnemonic):
                telescope(idx, instr.size, reg)
        idx += 2
        instr_seq = md.disasm(code[idx:], idx, 1)

    print("done!")

if __name__ == '__main__':
    main()

