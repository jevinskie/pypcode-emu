from __future__ import annotations

import collections
import mmap
import struct
from typing import Optional, Sequence, Union

import untangle
from elftools.elf.elffile import ELFFile
from lief import ELF
from pypcode import (
    Address,
    AddrSpace,
    Arch,
    Context,
    OpCode,
    PcodeOp,
    PcodePrettyPrinter,
    Translation,
    Varnode,
)

from pypcode_emu.utils import *


def sext(v, nbytes):
    return (v & ((1 << ((nbytes * 8) - 1)) - 1)) - (v & (1 << ((nbytes * 8) - 1)))


class UniqueBuf(dict):
    def __getitem__(self, key: slice) -> bytes:
        byte_off, byte_off_end, step = key.start, key.stop, key.step
        assert byte_off is not None and byte_off_end is not None
        assert step is None
        num_bytes = byte_off_end - byte_off
        return super().__getitem__((byte_off, num_bytes))

    def __setitem__(self, key: slice, value):
        byte_off, byte_off_end, step = key.start, key.stop, key.step
        assert byte_off is not None and byte_off_end is not None
        assert step is None
        num_bytes = byte_off_end - byte_off
        super().__setitem__((byte_off, num_bytes), value)


class PCodeEmu:
    def __init__(self, spec: str, entry: int = 0):
        arch, endianness, bitness, _ = spec.split(":")
        assert bitness == "32"
        langs = {l.id: l for arch in Arch.enumerate() for l in arch.languages}
        self.ctx = Context(langs[spec])
        self.entry = entry
        self.sla = untangle.parse(self.ctx.lang.slafile_path)
        self.ram = memoryview(mmap.mmap(-1, 0x1_0000_0000))
        self.register = memoryview(mmap.mmap(-1, 0x1000))
        self.space_bufs = {
            "ram": self.ram,
            "register": self.register,
        }
        self.ram_space = self.ctx.spaces["ram"]
        self.unique_space = self.ctx.spaces["unique"]
        self.register_space = self.ctx.spaces["register"]
        self.const_space = self.ctx.spaces["const"]
        self.inst_cache = {}
        self.bb_cache = {}
        reg_names = self.ctx.get_register_names()

        class Regs:
            pass

        self.regs = Regs()
        for reg_name in reg_names:
            setattr(Regs, reg_name, self.get_varnode_sym_prop(reg_name))
        self.regs.pc = self.entry
        self.regs.r1 = 0x8000_0000

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

        def getter(self) -> int:
            return unpack_from(space_buf, off)[0]

        def setter(self, val: int) -> None:
            pack_into(space_buf, off, val)

        return property(getter, setter)

    def space2buf(self, space: AddrSpace, unique: Optional[UniqueBuf] = None):
        return {
            self.ram_space: self.ram,
            self.register_space: self.register,
            self.unique_space: unique,
        }[space]

    def translate(self, addr: int):
        if addr in self.bb_cache:
            return self.bb_cache[addr]
        res = self.ctx.translate(self.ram[addr:], addr, bb_terminating=True)
        assert res.error is None
        unique = UniqueBuf()
        for insn in res.instructions:
            a = insn.address
            # FIXME: probably useless
            assert a.space is self.ram_space
            # FIXME: might be wrong
            assert a.offset not in self.inst_cache
            for op in insn.ops:
                opc = op.opcode
                if opc == OpCode.STORE:
                    space = op.inputs[0].get_space_from_const()
                    spacebuf = self.space2buf(space)
                    op.da = op.inputs[1]
                    op.aa = op.inputs[2]
                    addr_getter = self.getter_for_varnode(op.da, unique)

                    def store_setter(v: int):
                        addr = addr_getter()
                        print(f"*{space.name}[{addr:#010x}] := {v:#010x}")
                        spacebuf[addr : addr + op.aa.size] = v.to_bytes(
                            op.aa.size, space.endianness
                        )

                    op.d = store_setter
                    op.a = self.getter_for_varnode(op.aa, unique)
                elif opc == OpCode.LOAD:
                    op.da = op.output
                    op.d = self.setter_for_varnode(op.da, unique)
                    op.aa = op.inputs[1]
                    space = op.inputs[0].get_space_from_const()
                    spacebuf = self.space2buf(space)

                    def load_getter():
                        addr = addr_getter()
                        res = int.from_bytes(
                            spacebuf[addr : addr + op.aa.size], space.endianness
                        )
                        print(f"{res:#010x} = *{space.name}[{addr:#010x}]")
                        return res

                    op.a = load_getter
                else:
                    if op.output is not None:
                        op.da = op.output
                        op.d = self.setter_for_varnode(op.da, unique)
                    ninputs = len(op.inputs)
                    if ninputs >= 1:
                        op.aa = op.inputs[0]
                        op.a = self.getter_for_varnode(op.aa, unique)
                    if ninputs >= 2:
                        op.ba = op.inputs[1]
                        op.b = self.getter_for_varnode(op.ba, unique)
            self.inst_cache[a.offset] = insn
        self.bb_cache[addr] = res.instructions
        return res.instructions

    def getter_for_varnode(self, vn: Varnode, unique: UniqueBuf):
        if vn.space is self.unique_space:

            def get_unique():
                res = int.from_bytes(
                    unique[vn.offset : vn.offset + vn.size], vn.space.endianness
                )
                print(f"{res:#010x} = {vn}")
                return res

            return get_unique
        elif vn.space is self.const_space:
            return lambda: vn.offset
        elif vn.space is self.register_space:

            def get_register():
                res = int.from_bytes(
                    self.register[vn.offset : vn.offset + vn.size], vn.space.endianness
                )
                print(f"{res:#010x} = {vn.get_register_name()}")
                return res

            return get_register
        elif vn.space is self.ram_space:

            def get_ram():
                res = int.from_bytes(
                    self.ram[vn.offset : vn.offset + vn.size], vn.space.endianness
                )
                print(f"{res:#010x} = {vn}")
                return res

            return get_ram
        else:
            raise NotImplementedError(vn.space.name)

    def setter_for_varnode(self, vn: Varnode, unique: UniqueBuf):
        if vn.space is self.unique_space:

            def set_unique(v: int):
                if v < 0:
                    v = (1 << (vn.size * 8)) + v
                print(f"{vn} := {v:#010x}")
                unique[vn.offset : vn.offset + vn.size] = v.to_bytes(
                    vn.size, vn.space.endianness
                )

            return set_unique
        elif vn.space is self.const_space:
            raise ValueError("setting const?")
        elif vn.space is self.register_space:

            def set_register(v: int):
                if v < 0:
                    v = (1 << (vn.size * 8)) + v
                print(f"{vn.get_register_name()} := {v:#010x}")
                self.register[vn.offset : vn.offset + vn.size] = v.to_bytes(
                    vn.size, vn.space.endianness
                )

            return set_register
        elif vn.space is self.ram_space:

            def set_ram(v: int):
                if v < 0:
                    v = (1 << (vn.size * 8)) + v
                self.ram[vn.offset : vn.offset + vn.size] = v.to_bytes(
                    vn.size, vn.space.endianness
                )

            return set_ram
        else:
            raise NotImplementedError(vn.space.name)

    def emu_pcodeop(self, op: PcodeOp, idx: int) -> None:
        print(f"emu_pcodeop: op: {str(op)}")
        opc = op.opcode
        if opc is OpCode.INT_SEXT:
            op.d(sext(op.a(), op.aa.size))
        elif opc is OpCode.INT_ADD:
            op.d(sext(op.a(), op.aa.size) + sext(op.b(), op.ba.size))
        elif opc is OpCode.STORE:
            op.d(op.a())
        elif opc is OpCode.INT_EQUAL:
            op.d(op.a() == op.b())
        elif opc is OpCode.CBRANCH:
            # op.d()
            pass
        elif opc is OpCode.LOAD:
            op.d(op.a())
        elif opc is OpCode.BRANCHIND:
            pass
        else:
            raise NotImplementedError(str(op))

    def run(self):
        instrs = self.translate(self.regs.pc)
        idx = 0
        for instr in instrs:
            for op in instr.ops:
                self.emu_pcodeop(op, idx)
                idx += 1

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
