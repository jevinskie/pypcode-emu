import importlib.resources

from pypcode_emu import emu


def test_fact():
    test_dir = importlib.resources.files(__package__)
    fact_elf_path = test_dir / "samples" / "fact"
    e = emu.ELFPCodeEmu(fact_elf_path)
    i = e.translate(0x100003E4)
    e.dump_instr(i)
