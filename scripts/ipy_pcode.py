#!/usr/bin/env python3

import argparse

from elftools.elf.elffile import ELFError

from pypcode_emu.emu import ELFPCodeEmu, PCodeEmu

parser = argparse.ArgumentParser()
parser.add_argument("binary", help="Input binary file (binary/ELF)", metavar="BIN")
parser.add_argument("-e", "--entry", help="Entry point", metavar="ENTRY")
parser.add_argument("-s", "--spec", help="Specification", metavar="SPEC")
parser.add_argument(
    "-b", "--base", type=lambda x: int(x, 0), help="Base address", metavar="BASE"
)
args = parser.parse_args()
try:
    emu = ELFPCodeEmu(args.binary, args.entry)
except ELFError:
    emu = PCodeEmu(args.spec, args.binary, args.base, int(args.entry, 0))
instrs = emu.translate(emu.entry)
for i in instrs:
    for op in i.ops:
        emu.emu_pcodeop(op)
