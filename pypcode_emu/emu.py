import mmap

from elftools.elf.elffile import ELFFile
from pypcode import Arch, Context, PcodePrettyPrinter


class VarNode:
    def __init__(self):
        pass


class Instr:
    def __init__(self):
        pass


class PCodeEmu:
    def __init__(self, spec: str, base: int = 0):
        arch, endianness, bitness, _ = spec.split(":")
        assert bitness == "32"
        self.base = base
        self.ram = mmap.mmap(-1, 0xFFFF_FFFF)
        langs = {l.id: l for arch in Arch.enumerate() for l in arch.languages}
        self.ctx = Context(langs[spec])

    def translate(self, addr: int):
        res = self.ctx.translate(self.ram[addr : addr + 4], self.base, 1)
        for insn in res.instructions:
            print("-" * 80)
            print(
                "%08x/%d: %s %s"
                % (insn.address.offset, insn.length, insn.asm_mnem, insn.asm_body)
            )
            print("-" * 80)
            for op in insn.ops:
                print("%3d: %s" % (op.seq.uniq, str(op)))
            print("")

    def memcpy(self, addr: int, buf: bytes) -> None:
        self.ram[addr : addr + len(buf)] = buf


class ELFPCodeEmu(PCodeEmu):
    def __init__(self, elf_path: str):
        self.elf = ELFFile(open(elf_path, "rb"))
        machine = {
            "EM_MICROBLAZE": "mb",
        }[self.elf.header.e_machine]
        endianness = {
            "ELFDATA2MSB": "BE",
            "ELFDATA2LSB": "LE",
        }[self.elf.header.e_ident["EI_DATA"]]
        bitness = {
            "ELFCLASS32": "32",
            "ELFCLASS64": "64",
        }[self.elf.header.e_ident["EI_CLASS"]]
        super().__init__(f"{machine}:{endianness}:{bitness}:default")
        for seg_idx in range(self.elf.num_segments()):
            seg = self.elf.get_segment(seg_idx)
            if seg.header.p_type != "PT_LOAD":
                continue
            self.ram[
                seg.header.p_vaddr : seg.header.p_vaddr + seg.header.p_filesz
            ] = seg.data()
