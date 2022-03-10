from typing import Final

from filebytes.elf import ELF as ELFBase
from filebytes.elf import *

EM_MICROBLAZE: Final[int] = 189


class ELF(ELFBase):
    @property
    def header(self):
        return self.elfHeader.header

    @property
    def elf_class(self):
        return ELFCLASS(self.header.e_ident[EI.CLASS])

    @property
    def elf_data(self):
        return ELFDATA(self.header.e_ident[EI.DATA])
