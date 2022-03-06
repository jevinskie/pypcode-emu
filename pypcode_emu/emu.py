from __future__ import annotations

import collections
import mmap
import struct
import sys
import traceback
from typing import Callable, Optional, Sequence, Union

import untangle
from elftools.elf.elffile import ELFFile
from icecream import ic
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

real_print = print
print = lambda *args, **kwargs: real_print(*args, file=sys.stderr, **kwargs)

# from rich import print


def sext(v, nbytes):
    return (v & ((1 << ((nbytes * 8) - 1)) - 1)) - (v & (1 << ((nbytes * 8) - 1)))


def s2u(v, nbytes):
    if v < 0:
        return (1 << (nbytes * 8)) + v
    return v


def subpiece(v, nbytes, nbytes_out):
    return (v >> (nbytes * 8)) & ((1 << (nbytes_out * 8)) - 1)


class UniqueBuf(dict):
    def __getitem__(self, key: slice) -> bytes:
        byte_off, byte_off_end, step = key.start, key.stop, key.step
        assert byte_off is not None and byte_off_end is not None
        assert step is None
        num_bytes = byte_off_end - byte_off
        try:
            return super().__getitem__((byte_off, num_bytes))
        except KeyError as e:
            print(
                f"unique[{byte_off:#06x}:{num_bytes}] aka {byte_off} lookup error. Contents:"
            )
            for k, v in self.items():
                print(f"unique[{k[0]:#06x}:{k[1]}] = 0x{v.hex()}")
            sys.exit(-1)

    def __setitem__(self, key: slice, value):
        byte_off, byte_off_end, step = key.start, key.stop, key.step
        assert byte_off is not None and byte_off_end is not None
        assert step is None
        num_bytes = byte_off_end - byte_off
        super().__setitem__((byte_off, num_bytes), value)


class Int(int):
    addr: int
    size: int

    def __new__(cls, value: int, addr: int, size: int):
        res = int.__new__(cls, value)
        res.addr = addr
        res.size = size
        return res

    def sext(self, size: Optional[int] = None) -> int:
        if size is None:
            size = self.size
        return sext(self, size)

    def s2u(self) -> int:
        return s2u(self, self.size)


class PCodeEmu:
    def __init__(
        self,
        spec: str,
        entry: int = 0,
        initial_sp: int = 0x8000_0000,
        ret_addr: int = 0x7000_0000,
    ):
        arch, endianness, bitness, _ = spec.split(":")
        assert bitness == "32"
        langs = {l.id: l for arch in Arch.enumerate() for l in arch.languages}
        self.ctx = Context(langs[spec])
        self.entry = entry
        self.initial_sp = initial_sp
        self.ret_addr = ret_addr
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
        self.bb_cache = {}
        reg_names = self.ctx.get_register_names()

        class Regs:
            pass

        self.regs = Regs()
        for reg_name in reg_names:
            setattr(Regs, reg_name, self.get_varnode_sym_prop(reg_name))
        self.regs.pc = self.entry
        self.regs.r1 = self.initial_sp
        self.regs.r15 = self.ret_addr - 8

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

        def getter(self) -> Int:
            return Int(unpack_from(space_buf, off)[0], off, sz)

        def setter(self, val: Union[int, Int]) -> None:
            pack_into(space_buf, off, val)

        return property(getter, setter)

    def space2buf(self, space: AddrSpace, unique: Optional[UniqueBuf] = None):
        return {
            self.ram_space: self.ram,
            self.register_space: self.register,
            self.unique_space: unique,
        }[space]

    def translate(
        self,
        addr: int,
        max_inst: int = 0,
        max_bytes: int = 0,
        bb_terminating: bool = True,
    ) -> Sequence[Translation]:
        print(f"translate {addr:#010x}")
        if addr in self.bb_cache:
            return self.bb_cache[addr]
        res = self.ctx.translate(
            self.ram[addr:],
            addr,
            max_inst=max_inst,
            max_bytes=max_bytes,
            bb_terminating=bb_terminating,
        )
        if res.error is not None:
            raise RuntimeError(res.error)
        unique = UniqueBuf()
        for insn in res.instructions:
            a = insn.address
            # FIXME: probably useless
            print(a.space.name)
            assert a.space is self.ram_space
            for opc_idx, op in enumerate(insn.ops):
                opc = op.opcode
                if opc == OpCode.STORE:
                    store_space = op.inputs[0].get_space_from_const()
                    store_spacebuf = self.space2buf(store_space)
                    op.da = op.inputs[1]
                    op.aa = op.inputs[2]
                    op.ba = op.inputs[0]
                    store_addr_getter = self.getter_for_varnode(op.da, unique)

                    def make_store_setter(
                        store_addr_getter, store_spacebuf, op, store_space
                    ):
                        def store_setter(v: int):
                            store_addr = store_addr_getter()
                            print(
                                f"*{store_space.name}[{store_addr:#010x}] := {v:#010x}"
                            )
                            store_spacebuf[
                                store_addr : store_addr + op.aa.size
                            ] = v.to_bytes(op.aa.size, store_space.endianness)

                        return store_setter

                    op.d = make_store_setter(
                        store_addr_getter, store_spacebuf, op, store_space
                    )
                    op.a = self.getter_for_varnode(op.aa, unique)
                elif opc == OpCode.LOAD:
                    op.da = op.output
                    op.d = self.setter_for_varnode(op.da, unique)
                    op.aa = op.inputs[1]
                    load_space = op.inputs[0].get_space_from_const()
                    op.ba = op.inputs[0]
                    load_spacebuf = self.space2buf(load_space)
                    if op.aa.offset in (0x7E80, 0x8100):
                        print(
                            f"ok, SPACE1 IS: {load_space.name} op.aa.space: {op.aa.space.name} opc_idx: {opc_idx} off: {op.aa.offset:#x} addr: {op.address:#x} unique: {unique}"
                        )
                        traceback.print_stack()
                    load_addr_getter = self.getter_for_varnode(
                        lambda: op.inputs[1], unique
                    )

                    def make_load_getter(
                        load_addr_getter, load_spacebuf, op, load_space
                    ):
                        def load_getter():
                            print(
                                f"ok, SPACE2 IS: {load_space.name} op.aa.space: {op.aa.space.name} opc_idx: {opc_idx} off: {op.aa.offset:#x} addr: {op.address:#x} unique: {unique}"
                            )
                            traceback.print_stack()
                            load_addr = load_addr_getter()
                            res = int.from_bytes(
                                load_spacebuf[load_addr : load_addr + op.aa.size],
                                load_space.endianness,
                            )
                            print(
                                f"{res:#010x} = *{load_space.name}[{load_addr:#010x}]"
                            )
                            return res

                        return load_getter

                    op.a = make_load_getter(
                        load_addr_getter, load_spacebuf, op, load_space
                    )
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
        self.bb_cache[addr] = res.instructions
        return res.instructions

    def getter_for_varnode(self, vn: Union[Varnode, Callable], unique: UniqueBuf):
        if callable(vn):
            vn = vn()
        if vn.space is self.unique_space:

            def get_unique():
                if vn.offset in (0x7E80, 0x8100):
                    print(
                        f"get_unique vn: {vn} vn.offset: {vn.offset} space: {vn.space.name}"
                    )
                    print(f"get_unique unique: {unique}")
                    traceback.print_stack()
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
                if vn.offset in (
                    0x7E80,
                    0x8100,
                ):
                    print(
                        f"set_unique vn: {vn} vn.offset: {vn.offset} space: {vn.space.name}"
                    )
                    print(f"set_unique unique: {unique}")
                    traceback.print_stack()
                v = s2u(v, vn.size)
                print(f"{vn} := {v:#010x}")
                unique[vn.offset : vn.offset + vn.size] = v.to_bytes(
                    vn.size, vn.space.endianness
                )

            return set_unique
        elif vn.space is self.const_space:
            raise ValueError("setting const?")
        elif vn.space is self.register_space:

            def set_register(v: int):
                v = s2u(v, vn.size)
                print(f"{vn.get_register_name()} := {v:#010x}")
                self.register[vn.offset : vn.offset + vn.size] = v.to_bytes(
                    vn.size, vn.space.endianness
                )

            return set_register
        elif vn.space is self.ram_space:

            def set_ram(v: int):
                v = s2u(v, vn.size)
                self.ram[vn.offset : vn.offset + vn.size] = v.to_bytes(
                    vn.size, vn.space.endianness
                )

            return set_ram
        else:
            raise NotImplementedError(vn.space.name)

    def emu_pcodeop(self, op: PcodeOp) -> tuple[Optional[int], bool]:
        print(f"emu_pcodeop: {op.seq.uniq:3} {str(op)}")
        opc = op.opcode
        if opc is OpCode.INT_SEXT:
            op.d(sext(op.a(), op.aa.size))
        elif opc is OpCode.INT_ZEXT:
            op.d(op.a())
        elif opc is OpCode.INT_CARRY:
            op.d(op.a() + op.b() >= (2 << (op.aa.size * 8)))
        elif opc is OpCode.INT_SCARRY:
            s = sext(op.a(), op.aa.size) + sext(op.b(), op.aa.size)
            op.d(
                s >= (1 << (op.aa.size * 8 - 1))
                if s > 0
                else s < -(1 << (op.aa.size * 8 - 1))
            )
        elif opc is OpCode.INT_ADD:
            op.d(sext(op.a(), op.aa.size) + sext(op.b(), op.ba.size))
        elif opc is OpCode.INT_MULT:
            op.d(sext(op.a(), op.aa.size) * sext(op.b(), op.ba.size))
        elif opc is OpCode.STORE:
            op.d(op.a())
        elif opc is OpCode.LOAD:
            print(
                f"LOAD: d: {op.da} a: {op.aa} ba: {op.ba} space: {op.ba.get_space_from_const().name}"
            )
            v = op.a() & ((1 << (op.da.size * 8)) - 1)
            op.d(v)
        elif opc is OpCode.INT_EQUAL:
            op.d(op.a() == op.b())
        elif opc is OpCode.INT_NOTEQUAL:
            op.d(op.a() != op.b())
        elif opc is OpCode.INT_LEFT:
            op.d(op.a() << op.b())
        elif opc is OpCode.INT_RIGHT:
            op.d(op.a() >> op.b())
        elif opc is OpCode.INT_SRIGHT:
            op.d(sext(op.a(), op.aa.size) >> op.b())
        elif opc is OpCode.SUBPIECE:
            op.d(subpiece(op.a(), op.b(), op.da.size))
        elif opc is OpCode.INT_OR:
            op.d(op.a() | op.b())
        elif opc is OpCode.INT_AND:
            op.d(op.a() & op.b())
        elif opc is OpCode.INT_XOR:
            op.d(op.a() ^ op.b())
        elif opc is OpCode.COPY:
            op.d(op.a())
        elif opc is OpCode.CBRANCH:
            if op.b():
                return op.a(), False
        elif opc is OpCode.BRANCHIND:
            self.regs.pc = op.a()
            return None, True
        elif opc is OpCode.RETURN:
            self.regs.pc = op.a()
            return None, True
        elif opc is OpCode.CALLOTHER:
            assert op.a() == 0
            self.software_interrupt(op.b())
            return None, False
        else:
            raise NotImplementedError(str(op))
        return None, False

    def software_interrupt(self, int_num: int):
        print(f"got sw int: {int_num:#06x}", int_num)
        if int_num == 0x00008 and self.regs.r12 == 0x8000_0000:
            print(f"got checksum exit: {self.regs.r5:#010x}")

    def run(self):
        inst_num = 0
        inst_limit = 64 * 1e6
        while True:
            instrs = self.translate(self.regs.pc)
            num_instrs = len(instrs)
            for i, inst in enumerate(instrs):
                inst_num += 1
                if inst_num >= inst_limit:
                    print("bailing out due to max instr count")
                    return
                self.dump(inst)
                term = i == num_instrs - 1
                print(
                    f"instr len: {inst.length} delay: {inst.length_delay} term: {term}"
                )
                op_idx = 0
                num_ops = len(inst.ops)
                while op_idx < num_ops:
                    # ic(op_idx)
                    op = inst.ops[op_idx]
                    br_idx, is_term = self.emu_pcodeop(op)
                    # ic(br_idx)
                    if is_term:
                        print("bailing out of op emu due to terminator")
                        break
                    if br_idx is not None:
                        op_idx += br_idx
                    else:
                        op_idx += 1
                    print(f"end op_idx: {op_idx} num_ops: {num_ops}")
                if not is_term:
                    old_pc = self.regs.pc
                    new_pc = s2u(
                        old_pc.sext() + inst.length + inst.length_delay, old_pc.size
                    )
                    print(f"non-term jump from {old_pc:#010x} to {new_pc:#010x}")
                    self.regs.pc = new_pc
                if self.regs.pc == self.ret_addr:
                    print("bailing out due to ret_addr exit inner")
                print("inner op loop done!!!!!!!")
            print("outer loop done!!!")
            if self.regs.r1 == self.initial_sp:
                print("bailing out due to SP exit")
                break
            if self.regs.pc == self.ret_addr:
                print("bailing out due to ret_addr exit outer")
            print()

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
