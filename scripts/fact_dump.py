#!/usr/bin/env python3

from path import Path

from pypcode_emu.emu import ELFPCodeEmu

# fact_elf_bin = Path(__file__).parent.parent / "tests" / "pypcode_emu" / "samples" / "fact"
fact_elf_bin = Path(__file__).parent.parent / "fact"
emu = ELFPCodeEmu(fact_elf_bin)

bb_addrs = (
    (0x100000A0, True),
    (0x100000C8, True),
    (0x100000D8, True),
    (0x100000EC, True),
)

for bb_addr, has_delay_slot in bb_addrs:
    for instr in emu.translate(bb_addr):
        emu.dump(instr)
    if has_delay_slot:
        instr = emu.translate(
            instr.address.offset + instr.length, max_bytes=instr.length_delay
        )[0]
        emu.dump(instr)

    print("\n\n\n\n")
