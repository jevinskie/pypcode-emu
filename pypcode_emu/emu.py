from __future__ import annotations

import collections
import mmap
import struct
from typing import Optional, Sequence, Union

import untangle
from elftools.elf.elffile import ELFFile
from lief import ELF
from pypcode import Arch, Context, OpCode, PcodeOp, PcodePrettyPrinter, Translation

from pypcode_emu.utils import *


def sext8(v):
    return (v & ((1 << (8 - 1)) - 1)) - (v & (1 << (8 - 1)))


def sext16(v):
    return (v & ((1 << (16 - 1)) - 1)) - (v & (1 << (16 - 1)))


def sext32(v):
    return (v & ((1 << (32 - 1)) - 1)) - (v & (1 << (32 - 1)))


def sext64(v):
    return (v & ((1 << (64 - 1)) - 1)) - (v & (1 << (64 - 1)))


def emu_pcodeop(emu: PCodeEmu, op: PcodeOp):
    opc = op.opcode
    if opc is OpCode.INT_SEXT:
        pass
    elif opc is OpCode.INT_ADD:
        pass
    elif opc is OpCode.STORE:
        pass
    elif opc is OpCode.INT_EQUAL:
        pass
    elif opc is OpCode.CBRANCH:
        pass
    elif opc is OpCode.LOAD:
        pass
    elif opc is OpCode.BRANCHIND:
        pass
    else:
        raise NotImplementedError(str(op))


class PCodeEmu:
    def __init__(self, spec: str, entry: int = 0):
        arch, endianness, bitness, _ = spec.split(":")
        assert bitness == "32"
        langs = {l.id: l for arch in Arch.enumerate() for l in arch.languages}
        self.ctx = Context(langs[spec])
        self.entry = entry
        self.sla = untangle.parse(self.ctx.lang.slafile_path)
        self.ram = memoryview(mmap.mmap(-1, 0xFFFF_FFFF))
        self.register = memoryview(mmap.mmap(-1, 0x1000))
        self.space_bufs = {
            "ram": self.ram,
            "register": self.register,
        }
        self.ram_space = self.ctx.spaces["ram"]
        self.inst_cache = {}
        self.bb_cache = {}
        reg_names = self.ctx.get_register_names()

        class Regs:
            pass

        self.regs = Regs()
        for reg_name in reg_names:
            setattr(self.regs, reg_name, self.get_varnode_sym_prop(reg_name))
        self.regs.pc = self.entry

    def get_varnode_sym_prop(self, name: str):
        sym = first_where_key_is(self.sla.sleigh.symbol_table.varnode_sym, "name", name)
        assert sym is not None
        sz = int(sym["size"])
        space = first_where_key_is(self.sla.sleigh.spaces.space, "name", sym["space"])
        bigendian = space["bigendian"] == "true"
        space_buf = self.space_bufs[sym["space"]]
        off = int(sym["offset"], 16)

        struct_fmt = (">" if bigendian else "<") + {
            1: "B",
            2: "H",
            4: "I",
            8: "Q",
        }[sz]
        unpack_from = struct.Struct(struct_fmt).unpack_from
        pack_into = struct.Struct(struct_fmt).pack_into

        def getter() -> int:
            return unpack_from(space_buf, off)[0]

        def setter(val: int) -> None:
            pack_into(space_buf, off, val)

        return property(getter, setter)

    def translate(self, addr: int):
        if addr in self.bb_cache:
            return self.bb_cache[addr]
        res = self.ctx.translate(self.ram[addr:], addr, bb_terminating=True)
        assert res.error is None
        self.bb_cache[addr] = res.instructions
        for insn in res.instructions:
            a = insn.address
            # FIXME: probably useless
            assert a.space is self.ram_space
            # FIXME: might be wrong
            assert a.offset not in self.inst_cache
            self.inst_cache[a.offset] = insn
        return res.instructions

    def memcpy(self, addr: int, buf: bytes) -> None:
        self.ram[addr : addr + len(buf)] = buf

    @staticmethod
    def dump(instr: Union[Translation, Sequence[Translation]]):
        if not isinstance(instr, collections.Sequence):
            instr = (instr,)
        for insn in instr:
            print("-" * 80)
            print(
                "%08x/%d: %s %s"
                % (
                    insn.address.offset,
                    insn.length,
                    insn.asm_mnem,
                    insn.asm_body,
                )
            )
            print("-" * 80)
            for op in insn.ops:
                print("%3d: %s" % (op.seq.uniq, PcodePrettyPrinter.fmt_op(op)))
                print("\t\t%s" % str(op))
            print("")


class RawBinaryPCodeEmu(PCodeEmu):
    def __init__(self, spec: str, bin_path: str, base: int = 0, entry: int = 0):
        super().__init__(spec, entry)
        self.bin = open(bin_path, "rb").read()
        self.memcpy(base, self.bin)


class ELFPCodeEmu(PCodeEmu):
    def __init__(self, elf_path: str, entry: Optional[Union[str, int]] = None):
        self.elf = ELFFile(open(elf_path, "rb"))
        self.lelf = ELF.parse(elf_path)
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
        if entry is None:
            entry = self.elf.header.e_entry
        elif isinstance(entry, int):
            pass
        elif isinstance(entry, str):
            try:
                entry = int(entry, 0)
            except ValueError:
                entry = first_where_attr_is(self.lelf.symbols, "name", entry).value
        super().__init__(f"{machine}:{endianness}:{bitness}:default", entry)
        for seg_idx in range(self.elf.num_segments()):
            seg = self.elf.get_segment(seg_idx)
            if seg.header.p_type != "PT_LOAD":
                continue
            self.memcpy(seg.header.p_vaddr, seg.data())
