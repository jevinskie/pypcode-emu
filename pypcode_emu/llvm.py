from __future__ import annotations

import importlib.resources
import math
import os
import platform
from typing import Callable, ClassVar, Optional, Union

from bidict import bidict
from icecream import ic
from llvmlite import ir
from more_itertools import chunked
from path import Path
from pypcode import AddrSpace, PcodeOp, Varnode
from rich import inspect as rinspect
from wrapt import ObjectProxy

from .elf import PF, PT
from .emu import ELFPCodeEmu, UniqueBuf
from .llvm_utils import CStringPool
from .ntypes import (
    int8,
    int16,
    int32,
    int64,
    intN,
    nint,
    size2intN,
    size2uintN,
    uint8,
    uint16,
    uint32,
    uint64,
    uintN,
)
from .utils import gen_cmd

real_print = print
null_print = lambda *args, **kwargs: None

# dprint = null_print
dprint = real_print
iprint = real_print
eprint = real_print

CXX = gen_cmd(os.getenv("CXX", "clang++"))
LLVM_AS = gen_cmd(os.getenv("LLVM_AS", "llvm-as"))
LLVM_DIS = gen_cmd(os.getenv("LLVM_DIS", "llvm-dis"))
DEBUGIR = gen_cmd(os.getenv("DEBUGIR", "debugir"))
OPT = gen_cmd(os.getenv("LLVM_OPT", "opt"))

i1 = ir.IntType(1)
i8 = ir.IntType(8)
i16 = ir.IntType(16)
i32 = ir.IntType(32)
i64 = ir.IntType(64)
void = ir.VoidType()

size2iN = bidict({1: i8, 2: i16, 4: i32, 8: i64})


def ibN(nbytes: int) -> ir.Type:
    return size2iN[nbytes]


class IntVal(ObjectProxy):
    ctx: LLVMELFLifter  # Pycharm bug, should be ClassVar[LLVMELFLifter]
    _self_space: Optional[AddrSpace]
    _self_conc: Optional[nint]

    def __init__(self, v, space: Optional[AddrSpace], concrete: Optional[nint] = None):
        if isinstance(v, IntVal) and isinstance(ObjectProxy):
            v = v.w
        super().__init__(v)
        self._self_space = space
        if concrete is None and self.is_const:
            try:
                concrete = uintN(self.size)(int(self.constant))
            except ValueError:
                pass
        self._self_conc = concrete

    @classmethod
    def class_with_lifter(cls, lifter: LLVMELFLifter) -> type:
        return type("BoundIntVal", (IntVal,), {"ctx": lifter})

    @property
    def w(self):
        return self.__wrapped__

    def cmn_space(self, other: IntVal) -> Optional[AddrSpace]:
        if self.space is other.space:
            return self.space
        return None

    @property
    def space(self) -> Optional[AddrSpace]:
        return self._self_space

    @property
    def conc(self) -> nint:
        if self._self_conc is None:
            raise TypeError(f"{type(self)} is not concrete")
        return self._self_conc

    @property
    def size(self) -> int:
        assert self.type is not i1
        return {i8: 1, i16: 2, i32: 4, i64: 8}[self.type]

    @property
    def is_const(self) -> bool:
        return isinstance(self, ir.Constant)

    @property
    def c(self) -> ir.Constant:
        return super(ir.Constant, self)

    def sext(self, size: int) -> IntVal:
        if self.is_const:
            val = self.w.sext(ibN(size))
            c = self.conc.sext(size * 8)
            return type(self)(val, space=self.space, concrete=c)
        return type(self)(
            self.ctx.bld.sext(self, ibN(size), name="sext"), space=self.space
        )

    def zext(self, size: int) -> IntVal:
        if self.is_const:
            val = self.w.zext(ibN(size))
            c = self.conc.zext(size * 8)
            return type(self)(val, space=self.space, concrete=c)
        return type(self)(
            self.ctx.bld.zext(self, ibN(size), name="zext"), space=self.space
        )

    # these are dummy since, unlike python, everything is 2's compliment
    def s2u(self) -> IntVal:
        raise NotImplementedError
        print(f"s2u: {self}")
        return self

    def u2s(self) -> IntVal:
        raise NotImplementedError
        print(f"u2s: {self}")
        return self

    def bin_op(
        self,
        other: IntVal,
        op_name: str,
        llvm_name: Optional[str] = None,
        name: Optional[str] = None,
    ) -> IntVal:
        pretty_op_name = op_name.rstrip("_")
        dunder_op_name = f"__{pretty_op_name}__"
        if self.is_const and other.is_const:
            val_func = getattr(self.w, op_name)
            val = val_func(other)
            c_func = getattr(self.conc, dunder_op_name)
            c = c_func(other.conc)
            return type(self)(val, space=self.cmn_space(other), concrete=c)
        llvm_name = llvm_name or pretty_op_name
        op_bld_func = getattr(self.ctx.bld, llvm_name)
        name = name or op_name
        return type(self)(
            op_bld_func(self, other, name=name), space=self.cmn_space(other)
        )

    def bin_op(
        self,
        other: IntVal,
        op_name: str,
        llvm_name: Optional[str] = None,
        name: Optional[str] = None,
    ) -> IntVal:
        pretty_op_name = op_name.rstrip("_")
        dunder_op_name = f"__{pretty_op_name}__"
        if self.is_const and other.is_const:
            val_func = getattr(self.w, op_name)
            val = val_func(other)
            c_func = getattr(self.conc, dunder_op_name)
            c = c_func(other.conc)
            return type(self)(val, space=self.cmn_space(other), concrete=c)
        llvm_name = llvm_name or pretty_op_name
        op_bld_func = getattr(self.ctx.bld, llvm_name)
        name = name or op_name
        return type(self)(
            op_bld_func(self, other, name=name), space=self.cmn_space(other)
        )

    def cmp_op(
        self,
        op: str,
        other: IntVal,
        name: Optional[str] = None,
    ) -> IntVal:
        signed = op.startswith("s")
        signed_prefix = "s" if signed else ""
        uop = op.lstrip("s")
        if self.is_const and other.is_const:
            if signed:
                val = self.w.icmp_signed(uop, other)
            else:
                val = self.w.icmp_unsigned(uop, other)
            c = self.conc.cmp(op, other)
            return type(self)(val, space=self.cmn_space(other), concrete=c)
        name = f"_{name}" if name else ""
        val_name = f"{signed_prefix}{nint.CMP_MAP[uop]}{name}"
        if signed:
            val = self.ctx.bld.icmp_signed(uop, self, other, name=val_name)
        else:
            val = self.ctx.bld.icmp_unsigned(uop, self, other, name=val_name)
        return type(self)(val, space=self.cmn_space(other))

    def carry(self, other: IntVal) -> IntVal:
        if self.is_const and other.is_const:
            s = self.conc.as_u + other.conc.as_u
            int_max = (1 << (self.size * 8)) - 1
            val = 1 if s > int_max else 0
            return type(self)(i8(val), space=self.cmn_space(other), concrete=uint8(val))
        ovf_struct = self.ctx.bld.call(
            self.ctx.intrinsics.uadd_ovf[self.type], [self, other], name="uovf_s"
        )
        ovf_bit = self.ctx.bld.extract_value(ovf_struct, 1, name="uovf_bit")
        return type(self)(
            self.ctx.bld.zext(ovf_bit, i8, name="uovf_byte"),
            space=self.cmn_space(other),
        )

    def scarry(self, other: IntVal) -> IntVal:
        if self.is_const and other.is_const:
            s = self.conc.as_s + other.conc.as_s
            int_min = -(1 << (self.size * 8 - 1))
            int_max = (1 << (self.size * 8 - 1)) - 1
            val = 1 if not int_min <= s <= int_max else 0
            return type(self)(i8(val), space=self.cmn_space(other), concrete=uint8(val))
        ovf_struct = self.ctx.bld.call(
            self.ctx.intrinsics.sadd_ovf[self.type], [self, other], name="sovf_s"
        )
        ovf_bit = self.ctx.bld.extract_value(ovf_struct, 1, name="sovf_bit")
        return type(self)(
            self.ctx.bld.zext(ovf_bit, i8, name="sovf_byte"),
            space=self.cmn_space(other),
        )

    def asr(self, nbits: IntVal) -> IntVal:
        return self.bin_op(nbits, "asr", llvm_name="ashr")

    def __and__(self, other: IntVal) -> IntVal:
        return self.bin_op(other, "and_")

    def __add__(self, other: IntVal) -> IntVal:
        return self.bin_op(other, "add")

    def __mul__(self, other: IntVal) -> IntVal:
        return self.bin_op(other, "mul")

    def __lshift__(self, other: IntVal) -> IntVal:
        return self.bin_op(other, "lshift", llvm_name="shl", name="lsl")

    def __or__(self, other: IntVal) -> IntVal:
        return self.bin_op(other, "or_")

    def cmov(self, true_val: IntVal, false_val: IntVal) -> IntVal:
        if self.is_const:
            if self.conc:
                return true_val
            else:
                return false_val
        bool_v = self.cmp_op(
            "!=", type(self)(self.type(0), space=None), name="cmov_cond"
        )
        return type(self)(
            self.ctx.bld.select(bool_v, true_val, false_val, name="cmov_val"),
            space=true_val.cmn_space(false_val),
        )

    def slt(self, other: IntVal) -> IntVal:
        return self.cmp_op("s<", other)

    def __lt__(self, other: IntVal) -> IntVal:
        return self.cmp_op("<", other)

    def sle(self, other: IntVal) -> IntVal:
        return self.cmp_op("s<=", other)

    def __le__(self, other: IntVal) -> IntVal:
        return self.cmp_op("<=", other)

    def __eq__(self, other: IntVal) -> IntVal:
        return self.cmp_op("==", other)

    def __ne__(self, other: IntVal) -> IntVal:
        return self.cmp_op("!=", other)

    def sge(self, other: IntVal) -> IntVal:
        return self.cmp_op("s>=", other)

    def __ge__(self, other: IntVal) -> IntVal:
        return self.cmp_op(">=", other)

    def sgt(self, other: IntVal) -> IntVal:
        return self.cmp_op("s>", other)

    def __gt__(self, other: IntVal) -> IntVal:
        return self.cmp_op(">", other)


class Intrinsics:
    bswap_t = {ity: ir.FunctionType(ity, [ity]) for ity in (i16, i32, i64)}
    bswap: dict[type, ir.Function]

    nop: ir.Function
    nop_t = ir.FunctionType(void, [])

    add_ovf_t = {
        ity: ir.FunctionType(ir.LiteralStructType([ity, i1]), [ity, ity])
        for ity in (i16, i32, i64)
    }
    sadd_ovf: dict[type, ir.Function]
    uadd_ovf: dict[type, ir.Function]

    def __init__(self, m: ir.Module):
        self.bswap = {}
        for ity in self.bswap_t.keys():
            self.bswap[ity] = m.declare_intrinsic(
                f"llvm.bswap.{ity}", fnty=self.bswap_t[ity]
            )

        self.nop = m.declare_intrinsic("llvm.donothing", fnty=self.nop_t)

        self.sadd_ovf = {}
        self.uadd_ovf = {}
        for ity in self.add_ovf_t.keys():
            sadd_fname, uadd_fname = [
                f"llvm.{s}add.with.overflow.{ity}" for s in ("s", "u")
            ]
            self.sadd_ovf[ity] = m.declare_intrinsic(
                sadd_fname, fnty=self.add_ovf_t[ity]
            )
            self.uadd_ovf[ity] = m.declare_intrinsic(
                uadd_fname, fnty=self.add_ovf_t[ity]
            )


class LLVMELFLifter(ELFPCodeEmu):
    exec_start: int
    exec_end: int
    exe_path = Path
    m: ir.Module
    addr2bb: list[Optional[ir.Function]]
    bb_t: ir.FunctionType
    untrans_panic: ir.Function
    instr_len: int
    regs_t: ir.IdentifiedStructType
    regs_gv: ir.GlobalVariable
    mem_t: ir.ArrayType
    mem_gv: ir.GlobalVariable
    mem_lv: ir.LoadInstr
    mem_base_lv: ir.CastInstr
    bb_bbs: Optional[dict[tuple[int, int], ir.Block]]
    addr2bb_t: ir.Type
    addr2bb_gv: ir.GlobalVariable
    text_start_gv: ir.GlobalVariable
    bb_caller: ir.Function
    intrinsics: Intrinsics
    instr_cb: ir.Function
    op_cb: ir.Function
    bld: ir.IRBuilder
    bb_override: Optional[list[int]]
    asan: bool
    opt_level: str
    trace: bool
    strpool: CStringPool

    def __init__(
        self,
        elf_path: str,
        exe_path: str,
        entry: Optional[Union[str, int]] = None,
        instr_len: int = 4,
        bb_override: Optional[list[int]] = None,
        asan: bool = False,
        opt: str = "z",
        trace: bool = False,
    ):
        self.instr_len = instr_len
        assert self.instr_len == 4

        self.exe_path = Path(exe_path)
        self.exec_start = 0x1_0000_0000
        self.exec_end = 0x0000_0000

        self.bb_override = bb_override
        self.asan = asan
        self.opt_level = opt
        self.trace = trace

        self.m = self.get_init_mod()
        self.intrinsics = Intrinsics(self.m)
        self.bld = ir.IRBuilder()
        self.strpool = CStringPool(self.m)
        self.bb_bbs = None
        int_t = IntVal.class_with_lifter(self)

        super().__init__(elf_path, entry=entry, int_t=int_t)
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
        self.addr2bb = [None for _ in self.text_addrs_sentinel]

        if self.bitness == 32:
            self.iptr = i32
            self.isz = i32
        else:
            self.iptr = i64
            self.isz = i64

        self.untrans_panic = self.gen_utrans_panic_decl()
        self.instr_cb, self.op_cb = self.gen_cb_decls()

        self.gen_text_addrs()
        self.gen_addr2bb()
        self.bb_caller = self.gen_bb_caller()

    def init_reg_state(self):
        self.init_ir_regs(
            {
                "pc": self.entry,
                self.unalias_reg("sp"): self.initial_sp,
                self.unalias_reg("lr"): self.ret_addr - 8,
            }
        )

    @property
    def host_bitness(self):
        return {
            "32bit": 32,
            "64bit": 64,
        }[platform.architecture()[0]]

    @property
    def text_addrs(self):
        return range(self.exec_start, self.exec_end, self.instr_len)

    @property
    def text_addrs_sentinel(self):
        return [*self.text_addrs, self.exec_end]

    def addr2bb_idx(self, addr: int) -> int:
        assert addr % self.instr_len == 0
        assert self.exec_start <= addr <= self.exec_end
        return (addr - self.exec_start) // self.instr_len

    def get_init_mod(self) -> ir.Module:
        m = ir.Module(name=self.exe_path.name + ".ll")
        triple = {
            ("x86_64", "Linux", "glibc"): "x86_64-pc-linux-gnu",
        }.get((platform.machine(), platform.system(), platform.libc_ver()[0]))
        if triple:
            m.triple = triple
        return m

    def gen_reg_state(self):
        struct_mem_types = []
        for rname in self.ctx.get_register_names():
            reg = self.ctx.get_register(rname)
            struct_mem_types.append(ibN(reg.size))

        self.regs_t = self.m.context.get_identified_type("regs_t")
        self.regs_t.set_body(*struct_mem_types)
        self.regs_gv = ir.GlobalVariable(self.m, self.regs_t, "regs")

        # FIXME rename this function
        self.mem_t = ir.ArrayType(i8, 0x1_0000_0000).as_pointer()
        self.mem_gv = ir.GlobalVariable(self.m, self.mem_t, "mem")
        self.mem_lv = None

    def gen_addr2bb(self):
        self.bb_t = ir.FunctionType(void, [])
        self.addr2bb_t = ir.ArrayType(self.bb_t.as_pointer(), len(self.addr2bb))
        self.addr2bb_gv = ir.GlobalVariable(self.m, self.addr2bb_t, "addr2bb")
        self.addr2bb_gv.global_constant = True
        self.addr2bb_gv.linkage = "internal"

    def init_ir_regs(self, init: Optional[dict[str, int]] = None):
        if init is None:
            init = {}
        f = ir.Function(self.m, ir.FunctionType(void, []), name="regs_init")
        bb = f.append_basic_block(name="entry")
        self.bld.position_at_end(bb)
        for rname in self.ctx.get_register_names():
            reg = self.ctx.get_register(rname)
            setter = self.setter_for_varnode(reg, UniqueBuf())
            setter(ibN(reg.size)(init.get(rname, 0)))
        self.bld.ret_void()

    def global_var(self, name: str, ty: ir.Type, init) -> ir.GlobalVariable:
        gv = ir.GlobalVariable(self.m, ty, name)
        gv.global_constant = False
        gv.initializer = ty(init)
        return gv

    def global_const(self, name: str, ty: ir.Type, init) -> ir.GlobalVariable:
        gv = ir.GlobalVariable(self.m, ty, name)
        gv.global_constant = True
        gv.initializer = ty(init)
        return gv

    def get_register_prop(self, name: str) -> property:
        def getter(self) -> IntVal:
            raise NotImplementedError(f'get_register_prop getter called with "{name}"')

        def setter(self, val: Union[int, IntVal]) -> None:
            raise NotImplementedError(f'get_register_prop setter called with "{val}"')

        return property(getter, setter)

    def setter_for_store(self, store_addr_getter, store_spacebuf, op, store_space):
        assert store_space is self.ram_space

        def store_setter(v: IntVal):
            virt_store_addr = store_addr_getter()
            virt_store_addr_i64 = self.bld.zext(
                virt_store_addr, i64, "virt_store_addr_i64"
            )
            mapped_store_addr = self.bld.add(
                self.mem_base_lv, virt_store_addr_i64, name="mapped_store_addr"
            )
            store_ptr = self.bld.inttoptr(
                mapped_store_addr, v.type.as_pointer(), name="store_ptr"
            )
            bswap_v = self.gen_bswap(v)
            self.bld.store(bswap_v, store_ptr)

        return store_setter

    def getter_for_load(self, load_addr_getter, load_spacebuf, op, load_space):
        assert load_space is self.ram_space
        load_ty = ibN(op.da.size)

        def load_getter() -> IntVal:
            virt_load_addr = load_addr_getter()
            virt_load_addr_i64 = self.bld.zext(
                virt_load_addr, i64, "virt_load_addr_i64"
            )
            mapped_load_addr = self.bld.add(
                self.mem_base_lv, virt_load_addr_i64, name="mapped_load_addr"
            )
            load_ptr = self.bld.inttoptr(
                mapped_load_addr, load_ty.as_pointer(), name="load_ptr"
            )
            load_v = self.bld.load(load_ptr, name="load")
            return self.int_t(self.gen_bswap(load_v), space=self.ram_space)

        return load_getter

    def getter_for_varnode(
        self, vn: Union[Varnode, Callable], unique: UniqueBuf
    ) -> Callable[[], IntVal]:
        if callable(vn):
            vn = vn()
        if vn.space is self.unique_space:

            def get_unique() -> IntVal:
                return unique[vn.offset : vn.offset + vn.size]

            return get_unique
        elif vn.space is self.const_space:
            const_v = self.int_t(ibN(vn.size)(vn.offset), space=self.const_space)

            def get_constant() -> IntVal:
                return const_v

            return get_constant
        elif vn.space is self.reg_space:
            rname = vn.get_register_name()
            ridx = self.reg_idx(rname)

            def get_register() -> IntVal:
                gep = self.regs_gv.gep([i32(0), i32(ridx)])
                return self.int_t(
                    self.bld.load(gep, name=self.alias_reg(rname)), space=self.reg_space
                )

            return get_register
        elif vn.space is self.ram_space:

            def get_ram() -> IntVal:
                gep = self.bld.gep(
                    self.mem_lv,
                    [i64(0), i64(vn.offset)],
                    inbounds=True,
                    name="mem_load_gep",
                )
                load_t = ibN(vn.size)
                load_ptr = self.bld.bitcast(
                    gep, load_t.as_pointer(), name="mem_load_ptr"
                )
                load_val = self.bld.load(load_ptr, name="mem_load")
                bswapped = self.gen_bswap(load_val)
                return self.int_t(bswapped, space=self.ram_space)

            return get_ram
        else:
            raise NotImplementedError(vn.space.name)

    def setter_for_varnode(
        self, vn: Union[Varnode, Callable], unique: UniqueBuf
    ) -> Callable[[IntVal], None]:
        if callable(vn):
            vn = vn()
        if vn.space is self.unique_space:

            def set_unique(v: IntVal) -> None:
                unique[vn.offset : vn.offset + vn.size] = v

            return set_unique
        elif vn.space is self.const_space:
            raise ValueError("setting const?")
        elif vn.space is self.reg_space:
            rname = vn.get_register_name()
            ridx = self.reg_idx(rname)

            def set_register(v: IntVal) -> None:
                return self.bld.store(v, self.regs_gv.gep([i32(0), i32(ridx)]))

            return set_register
        elif vn.space is self.ram_space:

            def set_ram(v: IntVal) -> None:
                bswapped = self.gen_bswap(v)
                gep = self.bld.gep(
                    self.mem_lv,
                    [i64(0), i64(vn.offset)],
                    inbounds=True,
                    name="mem_store_gep",
                )
                store_t = ibN(vn.size)
                store_ptr = self.bld.bitcast(
                    gep, store_t.as_pointer(), name="mem_store_ptr"
                )
                self.bld.store(bswapped, store_ptr)

            return set_ram
        else:
            raise NotImplementedError(vn.space.name)

    def handle_cbranch(self, op: PcodeOp):
        tgt = op.a()
        cond_v = op.b()
        if cond_v.is_const:
            raise NotImplementedError("horray you found an optimization opportunity")
        if tgt.space is self.const_space:
            assert tgt.is_const
            true_bb = self.bb_bbs[(op.address, op.seq.uniq + tgt.conc.v)]
            false_bb = self.bb_bbs[(op.address, op.seq.uniq + 1)]
            self.bld.cbranch(cond_v, true_bb, false_bb)
            return tgt, True
        else:
            self.gen_bb_caller_call(tgt, tail=False)
            return None, True

    def handle_branchind(self, op: PcodeOp):
        # FIXME: constexpr
        self.gen_bb_caller_call(op.a())
        return None, True

    def handle_return(self, op: PcodeOp):
        # FIXME: constexpr
        self.gen_bb_caller_call(op.a())
        return None, True

    def handle_callind(self, op: PcodeOp):
        # FIXME: constexpr
        self.gen_bb_caller_call(op.a(), tail=False, ret=False)
        return None, False

    def handle_callother(self, op: PcodeOp):
        raise NotImplementedError

    def gen_bb_caller(self) -> ir.Function:
        fty = ir.FunctionType(void, [self.iptr])
        f = ir.Function(self.m, ftype=fty, name="bb_caller")
        bb = f.append_basic_block("entry")
        bb_addr = f.args[0]
        bb_addr.name = "bb_addr"
        self.bld.position_at_end(bb)
        text_start = self.iptr(self.exec_start)
        off_bytes = self.bld.sub(bb_addr, text_start, name="off_bytes")
        nbits_shift = int(math.log2(self.instr_len))
        assert math.log2(self.instr_len) == nbits_shift
        off_iptrs = self.bld.lshr(
            off_bytes, off_bytes.type(nbits_shift), name="off_iptrs"
        )
        bb_fptr_ptr = self.bld.gep(
            self.addr2bb_gv,
            [self.iptr(0), off_iptrs],
            inbounds=True,
            name="bb_fptr_ptr",
        )
        bb_fptr = self.bld.load(bb_fptr_ptr, name="bb_fptr")
        call = self.bld.call(bb_fptr, [], tail=True, name="bb_caller")
        self.bld.ret_void()
        return f

    def gen_bb_caller_call(self, bb_addr: IntVal, tail: bool = True, ret: bool = True):
        if bb_addr.is_const:
            call = self.bld.call(
                self.addr2bb[self.addr2bb_idx(bb_addr.conc.as_u)],
                [],
                tail=tail,
                name="bb_call_direct",
            )
        else:
            call = self.bld.call(self.bb_caller, [bb_addr], tail=tail, name="bb_call")
        if ret:
            self.bld.ret_void()

    def gen_instr_cb_call(self, bb: int, pc: int):
        self.bld.call(
            self.instr_cb, [self.iptr(bb), self.iptr(pc)], name="inst_cb_call"
        )

    def gen_op_cb_call(self, bb: int, pc: int, op_idx: int, opc: int):
        self.bld.call(
            self.op_cb,
            [self.iptr(bb), self.iptr(pc), i32(op_idx), i32(opc)],
            name="op_cb_call",
        )

    def gen_cb_decls(self):
        instr_cb_t = ir.FunctionType(void, [self.iptr, self.iptr])
        instr_cb = ir.Function(self.m, instr_cb_t, "instr_cb")
        op_cb_t = ir.FunctionType(void, [self.iptr, self.iptr, i32, i32])
        op_cb = ir.Function(self.m, op_cb_t, "op_cb")
        return instr_cb, op_cb

    def gen_utrans_panic_decl(self):
        untrans_panic_t = ir.FunctionType(void, [self.iptr])
        untrans_panic_t.args[0].name = "addr"
        return ir.Function(self.m, untrans_panic_t, "untrans_panic")

    def gen_untrans_panic_call(self, addr: int, f: ir.Function):
        bb = f.append_basic_block("entry")
        self.bld.position_at_end(bb)
        call = self.bld.call(
            self.untrans_panic, [self.iptr(addr)], tail=True, name="untrans_panic"
        )
        self.bld.ret_void()

    def gen_nop(self) -> ir.Instruction:
        return self.bld.call(self.intrinsics.nop, [])

    def gen_bswap(self, val: ir.Value) -> ir.Value:
        if self.bitness == self.host_bitness:
            return val
        name = f"{val.name}.bswap" if isinstance(val, ir.NamedValue) else "bswap"
        return self.bld.call(self.intrinsics.bswap[val.type], [val], name=name)

    def gen_text_addrs(self):
        self.text_start_gv = self.global_const("text_start", self.iptr, self.exec_start)
        self.global_const("text_end", self.iptr, self.exec_end)
        self.global_const("entry_point", self.iptr, self.entry)

    def init_addr2bb(self):
        self.addr2bb_gv.initializer = ir.Constant(self.addr2bb_t, self.addr2bb)

    def gen_bb_func(self, addr: int, f: ir.Function) -> Optional[ir.Function]:
        try:
            instrs = self.translate(addr)
        except RuntimeError as e:
            return None
        self.bb_bbs = {}

        prev_inst_last_bb = None
        for instr in instrs:
            inst_addr = instr.address.offset
            for i in range(len(instr.ops) + 1):
                bb = f.append_basic_block(f"pc_{inst_addr:#010x}_{i}")
                self.bb_bbs[(inst_addr, i)] = bb
                if i == 0 and prev_inst_last_bb:
                    with self.bld.goto_block(prev_inst_last_bb):
                        self.bld.branch(bb)
            prev_inst_last_bb = bb
        with self.bld.goto_block(bb):
            next_pc = self.int_t(
                self.iptr(instr.address.offset + instr.length + instr.length_delay),
                space=self.const_space,
            )
            self.gen_bb_caller_call(next_pc, tail=True)

        entry_bb = list(self.bb_bbs.items())[0][1]
        self.bld.position_at_end(entry_bb)
        self.mem_lv = self.bld.load(self.mem_gv, name="mem_ptr")
        self.mem_base_lv = self.bld.ptrtoint(self.mem_lv, i64, name="mem_base_int")

        for instr in instrs:
            inst_addr = instr.address.offset
            self.dump(instr)

            num_ops = len(instr.ops)
            for i, op in enumerate(instr.ops):
                order = op.seq.order
                print(f"i: {i} order: {order} uniq: {op.seq.uniq}")
                assert i == op.seq.uniq
                self.bld.position_at_end(self.bb_bbs[(inst_addr, i)])
                if self.trace:
                    if i == 0:
                        self.gen_instr_cb_call(addr, inst_addr)
                    self.gen_op_cb_call(addr, inst_addr, i, op.opcode.value)
                op_br_off, was_terminated = self.emu_pcodeop(op)
                if not was_terminated:
                    next_bb = self.bb_bbs[(inst_addr, i + 1)]
                    self.bld.branch(next_bb)

        return f

    def lift(self):
        self.lift_demo()
        addrs = self.text_addrs if self.bb_override is None else self.bb_override
        for addr in self.text_addrs_sentinel:
            f = ir.Function(self.m, self.bb_t, f"bb_{addr:#010x}")
            f.linkage = "internal"
            f.calling_convention = "fastcc"
            self.addr2bb[self.addr2bb_idx(addr)] = f
        translated_bbs = set()
        for addr in addrs:
            bb_idx = self.addr2bb_idx(addr)
            f = self.addr2bb[bb_idx]
            lifted_f = self.gen_bb_func(addr, f)
            if lifted_f:
                translated_bbs.add(addr)
        for addr in set(self.text_addrs_sentinel) - translated_bbs:
            bb_func = self.addr2bb[self.addr2bb_idx(addr)]
            self.gen_untrans_panic_call(addr, bb_func)
        self.init_addr2bb()
        self.compile(opt=self.opt_level, asan=self.asan)

    def lift_demo(self):
        # Create some useful types
        double = ir.DoubleType()
        fnty = ir.FunctionType(double, (double, double))

        # and declare a function named "fpadd" inside it
        func = ir.Function(self.m, fnty, name="fpadd")

        # Now implement the function
        bb = func.append_basic_block(name="entry")
        a, b = func.args
        a.name = "a"
        b.name = "b"
        self.bld.position_at_end(bb)
        result = self.bld.fadd(a, b, name="res")
        self.bld.ret(result)

    def write_ir(self, asm_out_path):
        open(asm_out_path, "w").write(str(self.m))

    def gen_lifted_regs_src(self, lifted_regs_cpp, lifted_regs_h):
        reg_names = self.ctx.get_register_names()
        # max_rname_len = max(map(len, reg_names))
        max_name_len = 7

        with open(lifted_regs_h, "w") as f:
            p = lambda *args, **kwargs: print(*args, **kwargs, file=f)
            p("#pragma once")
            p()
            p('#include "lifted-types.h"')
            p()
            p("typedef struct {")
            for rname in reg_names:
                reg = self.ctx.get_register(rname)
                p(f"    u{reg.size * 8} {rname};")
            p("} regs_t;")
            p()
            p('extern "C" regs_t regs;')
            p('extern "C" void regs_dump();')
            p('extern "C" void regs_dump_alias();')
            p('extern "C" void regs_init();')
            p()

        with open(lifted_regs_cpp, "w") as f:
            p = lambda *args, **kwargs: print(*args, **kwargs, file=f)
            p('#include "lifted-regs.h"')
            p()
            p("#include <fmt/format.h>")
            p("#include <fmt/color.h>")
            p("using namespace fmt;")
            p()
            p("regs_t regs;")
            p()

            def gen_reg_dump_func(func_name: str, alias_func=lambda n: n):
                p(f"void {func_name}() {{")
                for rnames in chunked(reg_names, 4):
                    fmt_str = "    ".join(
                        [f"{alias_func(n):{max_name_len}s}: {{}}" for n in rnames]
                    )
                    fmt_args = [
                        f"format(fg(regs.{n} ? color::pale_green : color::slate_blue), "
                        + f'"{{:#0{self.ctx.get_register(n).size * 2 + 2}x}}", regs.{n})'
                        for n in rnames
                    ]
                    p(f'    print("{fmt_str}\\n", {", ".join(fmt_args)});')
                p("}")
                p()

            gen_reg_dump_func("regs_dump")
            gen_reg_dump_func("regs_dump_alias", alias_func=self.alias_reg)

    def compile(self, opt: str = "z", asan: bool = False):
        build_dir = Path("build")
        try:
            os.mkdir(build_dir)
        except FileExistsError:
            pass

        fmt_inc_dir = (
            importlib.resources.files(__package__) / "native" / "fmt" / "include"
        )
        native_dir = importlib.resources.files(__package__) / "native"

        lifted_regs_cpp = build_dir / "lifted-regs.cpp"
        lifted_regs_h = build_dir / "lifted-regs.h"
        self.gen_lifted_regs_src(lifted_regs_cpp, lifted_regs_h)
        lifted_regs_o = lifted_regs_cpp + ".o"
        lifted_regs_s = lifted_regs_cpp + ".s"
        lifted_regs_ll = lifted_regs_cpp + ".ll"

        harness_cpp = native_dir / "harness.cpp"
        harness_base = Path("build") / harness_cpp.name
        harness_o = harness_base + ".o"
        harness_ll = harness_base + ".ll"
        harness_s = harness_base + ".s"

        lifted_bc_ll = build_dir / "lifted-bc.ll"
        lifted_bc_ll_orig = build_dir / "lifted-bc.orig.ll"
        lifted_bc_ll_orig_bak = lifted_bc_ll_orig + ".bak"
        self.write_ir(lifted_bc_ll_orig)
        lifted_bc_dbg_ll = build_dir / "lifted-bc.orig.dbg.ll"
        lifted_bc_comp_ll = build_dir / "lifted-bc.comp.ll"
        lifted_bc_comp_s = build_dir / "lifted-bc.comp.s"
        lifted_bc_o = lifted_bc_ll + ".o"
        lifted_bc_bc = lifted_bc_ll + ".bc"
        lifted_bc_opt_ll = lifted_bc_ll + ".opt.ll"
        lifted_bc_opt_s = lifted_bc_ll + ".opt.s"

        lifted_cpp = native_dir / "lifted.cpp"
        lifted_base = Path("build") / lifted_cpp.name
        lifted_o = lifted_base + ".o"
        lifted_ll = lifted_base + ".ll"
        lifted_s = lifted_base + ".s"

        lifted_segs_s = build_dir / "lifted-segs.s"
        self.gen_segs(lifted_segs_s)
        lifted_segs_o = lifted_segs_s + ".o"

        CXXFLAGS = [
            "-I",
            fmt_inc_dir,
            "-I",
            native_dir,
            "-I",
            build_dir,
            "-g",
            "-std=c++20",
            "-Wall",
            "-Wextra",
            f"-O{opt}",
        ]
        LDFLAGS = []
        LIBS = ["-lfmt"]

        PRETTY_CXXFLAGS = [*CXXFLAGS, "-Oz", "-g0"]

        if asan:
            CXXFLAGS += ["-fsanitize=address"]
            LDFLAGS += ["-fsanitize=address"]

        CXX(*CXXFLAGS, "-c", "-o", harness_o, harness_cpp)
        CXX(*CXXFLAGS, "-c", "-o", harness_s, "-S", harness_cpp, "-g0")
        CXX(*CXXFLAGS, "-c", "-o", harness_ll, "-S", "-emit-llvm", harness_cpp, "-g0")

        CXX(*CXXFLAGS, "-c", "-o", lifted_regs_o, lifted_regs_cpp)
        CXX(*CXXFLAGS, "-c", "-o", lifted_regs_s, "-S", lifted_regs_cpp, "-g0")
        CXX(
            *CXXFLAGS,
            "-c",
            "-o",
            lifted_regs_ll,
            "-S",
            "-emit-llvm",
            lifted_regs_cpp,
            "-g0",
        )

        CXX(*CXXFLAGS, "-c", "-o", lifted_segs_o, lifted_segs_s)

        lifted_bc_ll_orig.copy(lifted_bc_ll_orig_bak)
        # generate lifted_bc_dbg_ll, overwrites lifted_bc_ll_orig
        DEBUGIR(lifted_bc_ll_orig)
        # restore lifted_bc_ll_orig
        lifted_bc_ll_orig_bak.move(lifted_bc_ll_orig)
        # cleanup original asm
        LLVM_AS("-o", lifted_bc_bc, lifted_bc_ll_orig)
        LLVM_DIS("-o", lifted_bc_ll, lifted_bc_bc)

        lifted_bc_to_compile = lifted_bc_dbg_ll

        # compile debug IR
        CXX(*CXXFLAGS, "-c", "-o", lifted_bc_o, lifted_bc_to_compile)
        CXX(*CXXFLAGS, "-c", "-o", lifted_bc_comp_s, "-S", lifted_bc_to_compile, "-g0")
        CXX(
            *CXXFLAGS,
            "-c",
            "-o",
            lifted_bc_comp_ll,
            "-emit-llvm",
            "-S",
            lifted_bc_to_compile,
            "-g0",
        )
        CXX(*PRETTY_CXXFLAGS, "-c", "-o", lifted_bc_opt_s, "-S", lifted_bc_bc)
        CXX(
            *PRETTY_CXXFLAGS,
            "-c",
            "-o",
            lifted_bc_opt_ll,
            "-emit-llvm",
            "-S",
            lifted_bc_bc,
        )
        lifted_bc_bc.remove()

        CXX(*CXXFLAGS, "-c", "-o", lifted_o, lifted_cpp)
        CXX(*CXXFLAGS, "-c", "-o", lifted_s, "-S", lifted_cpp, "-g0")
        CXX(*CXXFLAGS, "-c", "-o", lifted_ll, "-S", "-emit-llvm", lifted_cpp, "-g0")

        CXX(
            *LDFLAGS,
            "-o",
            self.exe_path,
            lifted_bc_o,
            harness_o,
            lifted_o,
            lifted_regs_o,
            lifted_segs_o,
            *LIBS,
        )

    def gen_segs(self, asm_out_path):
        systy = platform.system().lower()
        rodata_sect = {"linux": ".rodata"}[systy]
        rodata_rel_sect = {"linux": ".data.rel.ro"}[systy]

        assert len(self.segments) < 256

        with open(asm_out_path, "w") as f:
            p = lambda *args, **kwargs: print(*args, **kwargs, file=f)

            num_segs = len(self.segments)
            ptr_t = {
                32: ".long",
                64: ".quad",
            }[self.bitness]
            host_ptr_t = {
                32: ".long",
                64: ".quad",
            }[self.host_bitness]

            p(f"\t.type\tnum_segs,@object")
            p(f'\t.section\t{rodata_sect},"a",@progbits')
            p(f"\t.globl\tnum_segs")
            p(f"num_segs:")
            p(f"\t.byte\t{num_segs}")
            p(f"\t.size\tnum_segs, 1")
            p()

            for seg in self.segments:
                seg_name = f"seg_{seg.vaddr:#010x}"
                p(f"\t.type\t{seg_name},@object")
                p(f'\t.section\t{rodata_sect},"a",@progbits')
                p(f"\t.globl\t{seg_name}")
                p(f"{seg_name}:")
                p(f"\t.byte\t{', '.join(map(hex, seg.bytes))}")
                p(f"\t.size\t{seg_name}, {len(seg.bytes)}")
                p()

            p(f"\t.type\tsegs,@object")
            p(f'\t.section\t{rodata_rel_sect},"aw",@progbits')
            p(f"\t.globl\tsegs")
            p(f"segs:")
            for seg in self.segments:
                seg_name = f"seg_{seg.vaddr:#010x}"
                p(f"\t{ptr_t}\t{seg.vaddr:#010x}")
                p(f"\t{ptr_t}\t{len(seg.bytes):#010x}")
                p(f"\t.byte\t{0 if (seg.header.p_flags & PF.WRITE) else 1}")
                p(f"\t{host_ptr_t}\t{seg_name}")
            p(f"\t.size\tsegs, {num_segs * (2 * 4 + 1 * self.host_bitness // 8)}")
            p()
