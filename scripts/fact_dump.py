#!/usr/bin/env python3

from path import Path

from pypcode_emu.emu import ELFPCodeEmu

# fact_elf_bin = Path(__file__).parent.parent / "tests" / "pypcode_emu" / "samples" / "fact"
fact_elf_bin = Path(__file__).parent.parent / "fact"
emu = ELFPCodeEmu(fact_elf_bin)

bb_addrs = (
    0x100000A0,
    0x100000C8,
    0x100000D8,
    0x100000EC,
)

for bb_addr in bb_addrs:
    for instr in emu.translate(bb_addr):
        emu.dump(instr)
    else:
        if instr.length_delay:
            delay_instrs = emu.translate(
                instr.address.offset + instr.length, max_bytes=instr.length_delay
            )
            for delay_instr in delay_instrs:
                emu.dump(delay_instr)

    print("\n\n\n\n")
