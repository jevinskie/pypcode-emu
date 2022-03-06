#!/usr/bin/env python3

import argparse
from pathlib import Path

from elftools.elf.elffile import ELFError

from pypcode_emu.emu import ELFPCodeEmu, PCodeEmu, s2u, sext

parser = argparse.ArgumentParser()
parser.add_argument("binary", help="Input binary file (binary/ELF)", metavar="BIN")
parser.add_argument("-e", "--entry", help="Entry point", metavar="ENTRY")
parser.add_argument("-s", "--spec", help="Specification", metavar="SPEC")
parser.add_argument(
    "-b", "--base", type=lambda x: int(x, 0), help="Base address", metavar="BASE"
)
args = parser.parse_args([str(Path(__file__).parent.parent / "rand2")])
try:
    emu = ELFPCodeEmu(args.binary, args.entry)
except ELFError:
    emu = PCodeEmu(args.spec, args.binary, args.base, int(args.entry, 0))
print(f"pc before: {emu.regs.pc:#010x}")
print(f"r1 before: {emu.regs.r1:#010x}")
print(f"r3 before: {emu.regs.r3:#010x}")
emu.regs.r5 = 5
print(f"r5 before: {emu.regs.r5:#010x}")
print(f"r15 before: {emu.regs.r15:#010x}")

emu.run_headless()

print(f"pc after: {emu.regs.pc:#010x}")
print(f"r1 after: {emu.regs.r1:#010x}")
print(f"r3 after: {emu.regs.r3:#010x}")
print(f"r5 after: {emu.regs.r5:#010x}")
print(f"r15 after: {emu.regs.r15:#010x}")
