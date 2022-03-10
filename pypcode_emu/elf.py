from typing import Final

from filebytes.elf import ELF as ELFBase
from filebytes.elf import *

from .utils import first_where

EM_MICROBLAZE: Final[int] = 189


class ELF(ELFBase):
    def __init__(self, filename: str, file_content: bytes = None):
        super().__init__(filename, fileContent=file_content)
        self.symbols = {}
        symtab = first_where(self.sections, lambda s: s.header.sh_type == SHT.SYMTAB)
        if symtab is not None:
            for sym in symtab.symbols:
                self.symbols[sym.name] = sym.header.st_value

    @property
    def header(self):
        return self.elfHeader.header

    @property
    def elf_class(self):
        return {
            0: ELFCLASS.NONE,
            1: ELFCLASS.BITS_32,
            2: ELFCLASS.BITS_64,
        }[self.header.e_ident[EI.CLASS]]

    @property
    def elf_data(self):
        return {
            0: ELFDATA.NONE,
            1: ELFDATA.LSB,
            2: ELFDATA.MSB,
        }[self.header.e_ident[EI.DATA]]
