import platform
from pathlib import Path
from typing import Optional, Union

from llvmlite import ir

from .elf import PF, PT
from .emu import ELFPCodeEmu

real_print = print
null_print = lambda *args, **kwargs: None

# dprint = null_print
dprint = real_print
iprint = real_print
eprint = real_print


class LLVMELFLifter(ELFPCodeEmu):
    m: ir.Module

    def __init__(
        self, elf_path: str, bc_path: str, entry: Optional[Union[str, int]] = None
    ):
        super().__init__(elf_path, entry=entry)
        self.bc_path = bc_path
        self.exec_start = 0x1_0000_0000
        self.exec_end = 0x0000_0000
        num_exec_segs = 0
        for seg in self.elf.segments:
            if seg.type != PT.LOAD or seg.header.p_flags & PF.EXEC == 0:
                continue
            assert seg.header.p_filesz == seg.header.p_memsz
            self.exec_start = min(self.exec_start, seg.vaddr)
            self.exec_end = max(self.exec_end, seg.vaddr + seg.header.p_filesz)
            num_exec_segs += 1
        assert num_exec_segs == 1
        iprint(f"exec start: {self.exec_start:#010x} end: {self.exec_end:#010x}")
        self.m = self._get_init_mod()

    def _get_init_mod(self):
        m = ir.Module(name=Path(self.bc_path).name)
        triple = {
            ("x86_64", "Linux", "glibc"): "x86_64-linux-gnu",
        }.get((platform.machine(), platform.system(), platform.libc_ver()[0]))
        if triple:
            m.triple = triple
        return m

    def lift(self):
        self.lift_demo()

    def lift_demo(self):
        print(self.m)
