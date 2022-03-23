import importlib.resources

from pypcode_emu import emu


def test_fact():
    test_dir = importlib.resources.files(__package__)
    fact_elf_path = test_dir / "samples" / "fact"
    e = emu.ELFPCodeEmu(fact_elf_path, entry="fact")
    i = e.translate(e.entry)
    e.dump(i)
