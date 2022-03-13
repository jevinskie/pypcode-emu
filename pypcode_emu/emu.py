from __future__ import annotations

import collections
import mmap
import struct
import time
from typing import Optional, Sequence, Union

import untangle
from pypcode import (
    AddrSpace,
    Arch,
    Context,
    OpCode,
    PcodeOp,
    PcodePrettyPrinter,
    Translation,
    Varnode,
)

from .elf import ELF, ELFCLASS, ELFDATA, EM_MICROBLAZE, PT, PhdrData
from .histogram import Histogram
from .utils import *

real_print = print
null_print = lambda *args, **kwargs: None
# print = lambda *args, **kwargs: real_print(*args, file=sys.stderr, **kwargs)

# dprint = null_print
dprint = real_print
iprint = real_print
eprint = real_print

# from rich import print


def sext(v, nbytes):
    return (v & ((1 << ((nbytes * 8) - 1)) - 1)) - (v & (1 << ((nbytes * 8) - 1)))


def s2u(v, nbytes):
    if v < 0:
        return (1 << (nbytes * 8)) + v
    return v


def subpiece(v, nbytes_trunc, nbytes_in, nbytes_out):
    # FIXME: iffy
    return (sext(v, nbytes_in) >> (nbytes_trunc * 8)) & ((1 << (nbytes_out * 8)) - 1)


class UniqueBuf(dict):
    def __getitem__(self, key: slice) -> bytes:
        byte_off, byte_off_end, step = key.start, key.stop, key.step
        assert byte_off is not None and byte_off_end is not None
        assert step is None
        num_bytes = byte_off_end - byte_off
        try:
            return super().__getitem__((byte_off, num_bytes))
        except KeyError as e:
            eprint(
                f"unique[{byte_off:#06x}:{num_bytes}] aka {byte_off} lookup error. Contents:"
            )
            for k, v in self.items():
                eprint(f"unique[{k[0]:#06x}:{k[1]}] = 0x{v.hex()}")
            sys.exit(-1)

    def __setitem__(self, key: slice, value):
        byte_off, byte_off_end, step = key.start, key.stop, key.step
        assert byte_off is not None and byte_off_end is not None
        assert step is None
        num_bytes = byte_off_end - byte_off
        super().__setitem__((byte_off, num_bytes), value)


class Int(int):
    size: int

    def __new__(cls, value: int, size: int):
        res = int.__new__(cls, value)
        res.size = size
        return res

    def sext(self, size: int) -> Int:
        return type(self)(sext(self, size), size)

    def s2u(self) -> Int:
        return type(self)(s2u(self, self.size), self.size)


class PCodeEmu:
    def __init__(
        self,
        spec: str,
        entry: int = 0,
        initial_sp: int = 0x8000_0000,
        ret_addr: int = 0x7000_0000,
        int_t: type = Int,
        arg0: int = 0,
    ):
        arch, endianness, bitness, _ = spec.split(":")
        assert bitness == "32"
        langs = {l.id: l for arch in Arch.enumerate() for l in arch.languages}
        self.ctx = Context(langs[spec])
        self.entry = entry
        self.initial_sp = initial_sp
        self.ret_addr = ret_addr
        self.int_t = int_t
        self.arg0 = arg0
        self.bitness = int(bitness)
        self.byteness = self.bitness // 8
        self.be = endianness == "BE"
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
        self.reg_names = self.ctx.get_register_names()
        self.reg_vns = [self.ctx.get_register(rn) for rn in self.reg_names]

        class Regs:
            pass

        self.regs = Regs()
        self.gen_reg_state()
        for reg_name in self.reg_names:
            setattr(Regs, reg_name, self.get_register_prop(reg_name))
        for real_reg_name, alias_reg_name in self.reg_aliases.items():
            setattr(Regs, alias_reg_name, getattr(Regs, real_reg_name))
        self.init_reg_state()
        self.last_csmith_checksum = None

    @property
    def reg_aliases(self):
        return UniqueBiDict(
            {
                "r1": "sp",
                "r15": "lr",
                "r5": "arg0",
                "r6": "arg1",
                "r7": "arg2",
                "r8": "arg3",
                "r9": "arg4",
                "r10": "arg5",
                "r3": "ret",
                "r4": "ret1",
                "r12": "int_num",
            }
        )

    def unalias_reg(self, reg_name: str) -> str:
        if reg_name in self.reg_names:
            return reg_name
        return self.reg_aliases[reg_name]

    def alias_reg(self, reg_name: str) -> str:
        if reg_name in self.reg_aliases.keys():
            return self.reg_aliases[reg_name]
        if reg_name not in self.reg_names:
            raise KeyError(reg_name)
        return reg_name

    def reg_idx(self, reg_name: str) -> int:
        reg_name = self.unalias_reg(reg_name)
        return self.reg_names.index(reg_name)

    def reg_vn(self, reg_name: str) -> Varnode:
        return self.reg_vns[self.reg_idx(reg_name)]

    def gen_reg_state(self):
        pass

    def init_reg_state(self):
        self.regs.pc = self.int_t(self.entry, self.byteness)
        self.regs.sp = self.int_t(self.initial_sp, self.byteness)
        self.regs.lr = self.int_t(self.ret_addr - 8, self.byteness)
        self.regs.arg0 = self.int_t(self.arg0, self.byteness)

    def get_register_prop(self, name: str) -> property:
        varnode = self.ctx.get_register(name)
        getter_func = self.getter_for_varnode(varnode, UniqueBuf())
        setter_func = self.setter_for_varnode(varnode, UniqueBuf())

        def getter(self) -> Int:
            return getter_func()

        def setter(self, val: Union[int, Int]) -> None:
            setter_func(val)

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
        # dprint(f"translate {addr:#010x}")
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
            assert a.space is self.ram_space
            for opc_idx, op in enumerate(insn.ops):
                opc = op.opcode
                if opc == OpCode.STORE:
                    store_space = op.inputs[0].get_space_from_const()
                    store_spacebuf = self.space2buf(store_space)
                    op.da = op.inputs[1]
                    op.aa = op.inputs[2]
                    op.ba = op.inputs[0]
                    # FIXME: need lambda?
                    store_addr_getter = self.getter_for_varnode(lambda: op.da, unique)

                    def make_store_setter(
                        store_addr_getter, store_spacebuf, op, store_space
                    ):
                        def store_setter(v: int):
                            store_addr = store_addr_getter()
                            store_spacebuf[
                                store_addr : store_addr + op.aa.size
                            ] = v.to_bytes(op.aa.size, store_space.endianness)

                        return store_setter

                    op.d = make_store_setter(
                        store_addr_getter, store_spacebuf, op, store_space
                    )
                    op.a = self.getter_for_varnode(lambda: op.aa, unique)
                elif opc == OpCode.LOAD:
                    op.da = op.output
                    op.d = self.setter_for_varnode(lambda: op.da, unique)
                    op.aa = op.inputs[1]
                    load_space = op.inputs[0].get_space_from_const()
                    op.ba = op.inputs[0]
                    load_spacebuf = self.space2buf(load_space)
                    load_addr_getter = self.getter_for_varnode(lambda: op.aa, unique)

                    def make_load_getter(
                        load_addr_getter, load_spacebuf, op, load_space
                    ):
                        def load_getter():
                            load_addr = load_addr_getter()
                            res = int.from_bytes(
                                load_spacebuf[load_addr : load_addr + op.da.size],
                                load_space.endianness,
                            )
                            # dprint(
                            #     f"{res:#010x} = *{load_space.name}[{load_addr:#010x}]"
                            # )
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

    def getter_for_varnode(
        self, vn: Union[Varnode, Callable], unique: UniqueBuf
    ) -> Callable[[], Int]:
        if callable(vn):
            vn = vn()
        if vn.space is self.unique_space:

            def get_unique() -> Int:
                return self.int_t(
                    int.from_bytes(
                        unique[vn.offset : vn.offset + vn.size], vn.space.endianness
                    ),
                    vn.size,
                )

            return get_unique
        elif vn.space is self.const_space:
            return lambda: self.int_t(vn.offset, vn.size)
        elif vn.space is self.register_space:

            def get_register() -> Int:
                return self.int_t(
                    int.from_bytes(
                        self.register[vn.offset : vn.offset + vn.size],
                        vn.space.endianness,
                    ),
                    vn.size,
                )

            return get_register
        elif vn.space is self.ram_space:

            def get_ram() -> Int:
                return self.int_t(
                    int.from_bytes(
                        self.ram[vn.offset : vn.offset + vn.size], vn.space.endianness
                    ),
                    vn.size,
                )

            return get_ram
        else:
            raise NotImplementedError(vn.space.name)

    def setter_for_varnode(
        self, vn: Union[Varnode, Callable], unique: UniqueBuf
    ) -> Callable[[Int], None]:
        if callable(vn):
            vn = vn()
        if vn.space is self.unique_space:

            def set_unique(v: Int):
                if not isinstance(v, self.int_t):
                    v = self.int_t(v, vn.size)
                else:
                    assert v.size == vn.size
                unique[vn.offset : vn.offset + vn.size] = v.s2u().to_bytes(
                    vn.size, vn.space.endianness
                )

            return set_unique
        elif vn.space is self.const_space:
            raise ValueError("setting const?")
        elif vn.space is self.register_space:

            def set_register(v: Int):
                if not isinstance(v, self.int_t):
                    v = self.int_t(v, vn.size)
                else:
                    assert v.size == vn.size
                self.register[vn.offset : vn.offset + vn.size] = v.s2u().to_bytes(
                    vn.size, vn.space.endianness
                )

            return set_register
        elif vn.space is self.ram_space:

            def set_ram(v: Int):
                if not isinstance(v, self.int_t):
                    v = self.int_t(v, vn.size)
                else:
                    assert v.size == vn.size
                self.ram[vn.offset : vn.offset + vn.size] = v.s2u().to_bytes(
                    vn.size, vn.space.endianness
                )

            return set_ram
        else:
            raise NotImplementedError(vn.space.name)

    def emu_pcodeop(self, op: PcodeOp) -> tuple[Optional[int], bool]:
        # dprint(f"emu_pcodeop: {op.seq.uniq:3} {str(op)}")
        opc = op.opcode
        if opc is OpCode.INT_SEXT:
            op.d(sext(op.a(), op.aa.size))
        elif opc is OpCode.INT_ZEXT:
            op.d(op.a())
        elif opc is OpCode.INT_CARRY:
            op.d(op.a() + op.b() >= (1 << (op.aa.size * 8)))
        elif opc is OpCode.INT_SCARRY:
            s = sext(op.a(), op.aa.size) + sext(op.b(), op.ba.size)
            op.d(
                s >= (1 << (op.aa.size * 8 - 1))
                if s > 0
                else s < -(1 << (op.aa.size * 8 - 1))
            )
        elif opc is OpCode.INT_ADD:
            op.d(op.a() + op.b() & ((1 << (op.da.size * 8)) - 1))
        elif opc is OpCode.INT_MULT:
            op.d(op.a() * op.b() & ((1 << (op.da.size * 8)) - 1))
        elif opc is OpCode.STORE:
            op.d(op.a())
        elif opc is OpCode.LOAD:
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
            op.d(subpiece(op.a(), op.b(), op.aa.size, op.da.size))
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
        elif opc is OpCode.CALLIND:
            self.regs.pc = op.a()
            return None, True
        elif opc is OpCode.CALLOTHER:
            assert op.a() == 0 and op.b() == 0x8
            self.software_interrupt(self.regs.int_num)
            return None, False
        else:
            raise NotImplementedError(str(op))
        return None, False

    def software_interrupt(self, int_num: int):
        iprint(f"got sw int: {int_num:#06x}", int_num)
        if int_num == 0x8000_0000:
            iprint(f"got Csmith checksum exit: {self.regs.arg0:#010x}")
            self.last_csmith_checksum = self.regs.arg0

    def run(self):
        inst_profile = Histogram()
        inst_num = 0
        inst_limit = 64 * 1e6
        self.last_csmith_checksum = None
        start_time = time.time()
        try:
            while True:
                instrs = self.translate(self.regs.pc)
                num_instrs = len(instrs)
                for i, inst in enumerate(instrs):
                    inst_num += 1
                    if inst_num >= inst_limit:
                        iprint("bailing out due to max instr count")
                        return
                    # self.dump(inst)
                    inst_profile[inst.asm_mnem] += 1
                    for binst in inst.delayslot_instructions:
                        inst_num += 1
                        # don't bother checking bailout condition here, next non-delay instr will trigger
                        # self.dump(binst)
                        inst_profile[binst.asm_mnem] += 1
                    # dprint(
                    #     f"instr len: {inst.length} delay: {inst.length_delay}"
                    # )
                    op_idx = 0
                    num_ops = len(inst.ops)
                    while op_idx < num_ops:
                        # ic(op_idx)
                        op = inst.ops[op_idx]
                        br_idx, is_term = self.emu_pcodeop(op)
                        # ic(br_idx)
                        if is_term:
                            # dprint("bailing out of op emu due to terminator")
                            break
                        if br_idx is not None:
                            op_idx += br_idx
                        else:
                            op_idx += 1
                        # dprint(f"end op_idx: {op_idx} num_ops: {num_ops}")
                    if not is_term:
                        old_pc = self.regs.pc
                        new_pc = s2u(
                            old_pc.sext() + inst.length + inst.length_delay, old_pc.size
                        )
                        # dprint(f"non-term jump from {old_pc:#010x} to {new_pc:#010x}")
                        self.regs.pc = new_pc
                    if self.regs.pc == self.ret_addr:
                        iprint("bailing out due to ret_addr exit inner")
                    # dprint("inner op loop done!!!!!!!")
                # dprint("outer loop done!!!")
                if self.regs.r1 == self.initial_sp:
                    iprint("bailing out due to SP exit")
                    break
                if self.regs.pc == self.ret_addr:
                    iprint("bailing out due to ret_addr exit outer")
                    break
        finally:
            end_time = time.time()
            iprint()
            if self.last_csmith_checksum is not None:
                iprint(f"Csmith checksum: {self.last_csmith_checksum:#010x}")
            duration = end_time - start_time
            instr_per_sec = inst_num / duration
            iprint(
                f"num instrs run: {inst_num:,} time: {duration:.2f} s inst / sec: {int(instr_per_sec):,}"
            )

            iprint(inst_profile.ascii_histogram())

    def memcpy(self, addr: int, buf: bytes) -> None:
        self.ram[addr : addr + len(buf)] = buf

    @staticmethod
    def dump(instr: Union[Translation, Sequence[Translation]]):
        if not isinstance(instr, collections.Sequence):
            instr = (instr,)
        for insn in instr:
            dprint("-" * 80)
            dprint(
                "%08x/%d: %s %s"
                % (
                    insn.address.offset,
                    insn.length,
                    insn.asm_mnem,
                    insn.asm_body,
                )
            )
            dprint("-" * 80)
            for op in insn.ops:
                dprint("%3d: %s" % (op.seq.uniq, PcodePrettyPrinter.fmt_op(op)))
                dprint("\t\t%s" % str(op))


class RawBinaryPCodeEmu(PCodeEmu):
    def __init__(
        self, spec: str, bin_path: str, base: int = 0, entry: int = 0, int_t: type = Int
    ):
        super().__init__(spec, entry, int_t=int_t)
        self.bin = open(bin_path, "rb").read()
        self.memcpy(base, self.bin)


class ELFPCodeEmu(PCodeEmu):
    elf: ELF
    segments: [PhdrData]

    def __init__(
        self,
        elf_path: str,
        entry: Optional[Union[str, int]] = None,
        arg0: int = 0,
        int_t: type = Int,
    ):
        self.elf = ELF(elf_path)
        machine = {
            EM_MICROBLAZE: "mb",
        }[self.elf.header.e_machine]
        endianness = {
            ELFDATA.MSB: "BE",
            ELFDATA.LSB: "LE",
        }[self.elf.elf_data]
        bitness = {
            ELFCLASS.BITS_32: "32",
            ELFCLASS.BITS_64: "64",
        }[self.elf.elf_class]
        if entry is None:
            entry = self.elf.header.e_entry
        elif isinstance(entry, int):
            pass
        elif isinstance(entry, str):
            try:
                entry = int(entry, 0)
            except ValueError:
                assert entry in self.elf.symbols
                entry = self.elf.symbols[entry]
        super().__init__(
            f"{machine}:{endianness}:{bitness}:default", entry, arg0=arg0, int_t=int_t
        )
        self.segments = []
        for seg in self.elf.segments:
            if seg.type != PT.LOAD:
                continue
            self.segments.append(seg)
            self.memcpy(seg.vaddr, seg.bytes)
