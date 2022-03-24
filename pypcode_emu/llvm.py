from __future__ import annotations

import importlib.resources
import math
import os
import platform
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, ClassVar, Optional, Type, Union

import colorful as cf
from bidict import bidict
from icecream import ic
from llvmlite import ir
from more_itertools import chunked
from path import Path
from pypcode import AddrSpace, PcodeOp, Translation, Varnode
from rich import inspect as rinspect
from rich import print as rprint
from wrapt import ObjectProxy

from .elf import PF, PT
from .emu import ELFPCodeEmu, SpaceContext, ValBuf
from .llvm_utils import CStringPool
from .ntypes import (
    int8,
    int16,
    int32,
    int64,
    intN,
    nint,
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

PRINTF_FMT_RE = re.compile("(%(p|d|u|x|s))|(0x%x)|(%%)")

cf.use_true_colors()
cf.update_palette(
    {
        "slateblue": "#6A5ACD",
        "palegreen": "#98FB98",
    }
)


def ibN(nbytes: int) -> ir.Type:
    return size2iN[nbytes]


class IntVal(ObjectProxy):
    ctx: LLVMELFLifter  # Pycharm bug, should be ClassVar[LLVMELFLifter]
    _self_space: Optional[AddrSpace]
    _self_conc: Optional[nint]
    _self_exprs: tuple[IntVal]

    def __init__(
        self,
        v,
        space: Optional[AddrSpace] = None,
        concrete: Optional[nint] = None,
        exprs: Optional[tuple] = None,
    ):
        assert not isinstance(v, ObjectProxy)
        if isinstance(v, IntVal) and isinstance(v, ObjectProxy):
            assert False
            v = v.w
        super().__init__(v)
        self._self_space = space
        if concrete is None and self.is_const:
            try:
                cval = int(self.constant)
                if isinstance(self.type, ir.IntType):
                    concrete = uintN(self.type.width // 8)(cval)
                elif isinstance(self.type, ir.PointerType):
                    concrete = uintN(self.size)(cval)
                else:
                    raise TypeError(f"IR type: {self.type} self: {self.m}")
            except ValueError:
                pass

        self._self_conc = concrete

        if exprs is None:
            if concrete is not None:
                self._self_exprs = (concrete,)
            # elif isinstance(self.w, vv)
            else:
                self._self_exprs = (self,)
        else:
            self._self_exprs = exprs

    @classmethod
    def class_with_lifter(cls, lifter: LLVMELFLifter) -> Type[IntVal]:
        return type("BoundIntVal", (IntVal,), {"ctx": lifter})

    @property
    def w(self):
        return self.__wrapped__

    def __repr__(self):
        return f"<IntVal for {repr(self.w)}>"

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
    def exprs(self):
        return self._self_exprs

    @property
    def size(self) -> int:
        assert self.type is not i1
        return {i8: 1, i16: 2, i32: 4, i64: 8, ir.PointerType: self.ctx.iptr.size}[
            self.type
        ]

    @property
    def is_const(self) -> bool:
        return isinstance(self, ir.Constant)

    @property
    def c(self) -> ir.Constant:
        return super(ir.Constant, self)

    @property
    def has_const_ops(self):
        return isinstance(self, ir.values._ConstOpMixin)

    # def __hash__(self):
    #     if isinstance(self.w,

    def comp_time_eq(self, other: IntVal) -> bool:
        raise NotImplementedError
        if self.is_const and other.is_const:
            return self.conc.strict_eq(other.conc)
        if len(self.exprs) != len(other.exprs):
            return False

        def rec_eq(a, b):
            if isinstance(a, tuple):
                if not isinstance(b, tuple):
                    return False
                if len(a) != len(b):
                    return False

                for a_sub, b_sub in zip(a, b):
                    if not rec_eq(a_sub, b_sub):
                        return False
                return True
            elif isinstance(a, str):
                if not isinstance(b, str):
                    return False
                return a == b
            elif isinstance(a, ir.NamedValue):
                if not isinstance(b, ir.NamedValue):
                    return False
                return a.name == b.name
            else:
                return a.comp_time_eq(b)

        return rec_eq(self.exprs, other.exprs)

    def sext(self, size: int) -> IntVal:
        if self.is_const:
            val = self.w.sext(ibN(size))
            c = self.conc.sext(size * 8)
            return type(self)(val, space=self.space, concrete=c)
        exprs = ("sext", self.exprs)
        return type(self)(
            self.ctx.bld.sext(self, ibN(size), name="sext"),
            space=self.space,
            exprs=exprs,
        )

    def zext(self, size: int) -> IntVal:
        if self.is_const:
            val = self.w.zext(ibN(size))
            c = self.conc.zext(size * 8)
            return type(self)(val, space=self.space, concrete=c)
        exprs = ("zext", self.exprs)
        return type(self)(
            self.ctx.bld.zext(self, ibN(size), name="zext"),
            space=self.space,
            exprs=exprs,
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
        llvm_name = llvm_name or op_name
        name = name or op_name
        if self.is_const and other.is_const:
            val_func = getattr(self.w, llvm_name)
            val = val_func(other)
            c_func = getattr(self.conc, dunder_op_name)
            c = c_func(other.conc)
            return type(self)(val, space=self.cmn_space(other), concrete=c)
        op_bld_func = getattr(self.ctx.bld, llvm_name)
        exprs = (pretty_op_name, self.exprs, other.exprs)
        return type(self)(
            op_bld_func(self, other, name=name),
            space=self.cmn_space(other),
            exprs=exprs,
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
            c = self.conc.cmp(op, other.conc)
            return type(self)(val, space=self.cmn_space(other), concrete=c)
        name = f"_{name}" if name else ""
        val_name = f"{signed_prefix}{nint.CMP_MAP[uop]}{name}"
        if signed:
            val = self.ctx.bld.icmp_signed(uop, self, other, name=val_name)
        else:
            val = self.ctx.bld.icmp_unsigned(uop, self, other, name=val_name)
        exprs = (op, self.exprs, other.exprs)
        return type(self)(val, space=self.cmn_space(other), exprs=exprs)

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
        exprs = ("carry", self.exprs, other.exprs)
        return type(self)(
            self.ctx.bld.zext(ovf_bit, i8, name="uovf_byte"),
            space=self.cmn_space(other),
            exprs=exprs,
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
        exprs = ("scarry", self.exprs, other.exprs)
        return type(self)(
            self.ctx.bld.zext(ovf_bit, i8, name="sovf_byte"),
            space=self.cmn_space(other),
            exprs=exprs,
        )

    def bitcast(self, new_ty: ir.Type) -> IntVal:
        if self.is_const:
            val = self.w.bitcast(new_ty)
            c = nint(self.conc.v, new_ty.width, self.conc.s)
            return type(self)(val, space=self.space, concrete=c)
        else:
            exprs = ("bitcast", self.exprs, new_ty)
            return type(self)(self.bld.bitcast(new_ty), space=self.space, exprs=exprs)

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
        exprs = ("cmov", bool_v.exprs, true_val.exprs, false_val.exprs)
        return type(self)(
            self.ctx.bld.select(bool_v, true_val, false_val, name="cmov_val"),
            space=true_val.cmn_space(false_val),
            exprs=exprs,
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


class RegBuf(ValBuf):
    name = "register"


class MemBuf(dict):
    pass


class LLVMSpaceContext(SpaceContext):
    regs: RegBuf
    written_regs: RegBuf
    reg_gens: defaultdict[int]
    mem: MemBuf
    written_mem: MemBuf

    def __init__(self):
        super().__init__()
        self.regs = RegBuf()
        self.written_regs = RegBuf()
        self.reg_gens = defaultdict(int)
        self.mem = MemBuf()
        self.written_mem = MemBuf()


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
    regs_lv: ir.Argument
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
    msan: bool
    opt_level: str
    trace: bool
    strpool: CStringPool
    printf: ir.Function
    exit: ir.Function
    regs_dump: ir.Function
    regs_dump_alias: ir.Function
    inline: bool
    assertions: bool
    debugtrap: ir.Function
    sctx: LLVMSpaceContext

    def __init__(
        self,
        elf_path: str,
        exe_path: str,
        entry: Optional[Union[str, int]] = None,
        instr_len: int = 4,
        bb_override: Optional[list[int]] = None,
        asan: bool = False,
        msan: bool = False,
        opt: str = "z",
        trace: bool = False,
        arg0: int = 0,
        inline: bool = False,
        assertions: bool = True,
    ):
        self.instr_len = instr_len
        assert self.instr_len == 4

        self.exe_path = Path(exe_path)
        self.exec_start = 0x1_0000_0000
        self.exec_end = 0x0000_0000

        self.trace_pad = " " * 48

        self.bb_override = bb_override
        self.asan, self.msan = asan, msan
        self.opt_level = opt
        self.trace = trace
        self.inline = inline
        self.assertions = assertions

        self.m = self.get_init_mod()
        self.intrinsics = Intrinsics(self.m)
        self.bld = ir.IRBuilder()
        int_t = IntVal.class_with_lifter(self)
        self.strpool = CStringPool(self.m, int_t)
        self.printf = self.gen_printf_decl()
        self.exit = self.gen_exit_decl()
        self.bb_bbs = None
        self.sctx = None

        super().__init__(
            elf_path, entry=entry, int_t=int_t, sctx_t=LLVMSpaceContext, arg0=arg0
        )
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
        self.regs_dump, self.regs_dump_alias = self.gen_regs_dump_decls()

        debugtrap_t = ir.FunctionType(void, [])
        self.debugtrap = self.m.declare_intrinsic("llvm.debugtrap", fnty=debugtrap_t)

        self.gen_text_addrs()
        self.gen_addr2bb()
        self.bb_caller = self.gen_bb_caller()

    def init_reg_state(self):
        self.init_ir_regs(
            {
                "pc": self.entry,
                self.unalias_reg("sp"): self.initial_sp,
                self.unalias_reg("lr"): self.ret_addr - 8,
                self.unalias_reg("arg0"): self.arg0,
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
        self.regs_lv = None

        # FIXME rename this function
        self.mem_t = ir.ArrayType(i8, 0x1_0000_0000).as_pointer()
        self.mem_lv = None

    def gen_addr2bb(self):
        self.bb_t = ir.FunctionType(void, [self.mem_t, self.regs_t.as_pointer()])
        self.addr2bb_t = ir.ArrayType(self.bb_t.as_pointer(), len(self.addr2bb))
        self.addr2bb_gv = ir.GlobalVariable(self.m, self.addr2bb_t, "addr2bb")
        self.addr2bb_gv.global_constant = True
        self.addr2bb_gv.linkage = "internal"

    def init_ir_regs(self, init: Optional[dict[str, int]] = None):
        if init is None:
            init = {}
        f = ir.Function(
            self.m, ir.FunctionType(void, [self.regs_t.as_pointer()]), name="regs_init"
        )
        bb = f.append_basic_block(name="entry")
        regs_ptr = self.int_t(f.args[0])
        regs_ptr.name = "regs_ptr"
        self.bld.position_at_end(bb)
        self.regs_lv = regs_ptr
        for rname in self.ctx.get_register_names():
            reg = self.ctx.get_register(rname)
            setter = self.setter_for_varnode(reg)
            setter(self.int_t(ibN(reg.size)(init.get(rname, 0))))
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

    def setter_for_store(
        self,
        store_addr_getter,
        store_spacebuf,
        op,
        store_space,
        sctx: LLVMSpaceContext,
        force: bool = False,
    ):
        assert store_space is self.ram_space

        def store_setter(v: IntVal):
            virt_store_addr = store_addr_getter()
            sctx.mem[virt_store_addr.exprs] = v
            sctx.written_mem[virt_store_addr.exprs] = (virt_store_addr, v)
            if self.trace:
                force_str = " [forced]" if force else ""
                self.gen_printf(
                    f"{self.trace_pad}*%p = 0x%x{force_str}\n", virt_store_addr, v
                )
            if not force:
                return
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

    def getter_for_load(
        self,
        load_addr_getter,
        load_spacebuf,
        op,
        load_space,
        sctx: LLVMSpaceContext,
        force: bool = False,
    ):
        assert load_space is self.ram_space
        load_ty = ibN(op.da.size)

        def load_getter() -> IntVal:
            virt_load_addr = load_addr_getter()
            attr_str = " [forced]" if force else ""
            if virt_load_addr.exprs in sctx.mem and not force:
                res = sctx.mem[virt_load_addr.exprs]
                attr_str += " [cached]"
            else:
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
                exprs = ("load", virt_load_addr)
                res = self.int_t(
                    self.gen_bswap(load_v), space=self.ram_space, exprs=exprs
                )
                sctx.mem[virt_load_addr.exprs] = res
            if self.trace:
                self.gen_printf(
                    f"{self.trace_pad}0x%x = *%p{attr_str}\n", res, virt_load_addr
                )
            return res

        return load_getter

    def getter_for_varnode(
        self,
        vn: Union[Varnode, Callable],
        sctx: Optional[LLVMSpaceContext] = None,
        op: Optional[PcodeOp] = None,
        force: bool = False,
    ) -> Callable[[], IntVal]:
        if callable(vn):
            vn = vn()
        sctx = sctx or self.sctx_t()
        if vn.space is self.unique_space:

            def get_unique() -> IntVal:
                res = sctx.unique[vn.offset : vn.offset + vn.size]
                if self.trace:
                    self.gen_printf(f"{self.trace_pad}0x%x = {vn}\n", res)
                return res

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
                attr_str = " [forced]" if force else ""
                if (vn.offset, vn.size) in sctx.regs and not force:
                    res = sctx.regs[vn.offset : vn.offset + vn.size]
                    attr_str += " [cached]"
                else:
                    if self.regs_lv.has_const_ops:
                        gep = self.regs_lv.gep([i32(0), i32(ridx)])
                    else:
                        gep = self.bld.gep(
                            self.regs_lv,
                            [i32(0), i32(ridx)],
                            inbounds=True,
                            name=f"{self.alias_reg(rname)}_ld_ptr",
                        )
                    arname = self.alias_reg(rname)
                    res_v = self.bld.load(gep, name=arname)
                    exprs = ("reg", f"{arname}_{sctx.reg_gens[arname]}")
                    res = self.int_t(res_v, space=self.reg_space, exprs=exprs)
                    sctx.regs[vn.offset : vn.offset + vn.size] = res
                if self.trace:
                    pretty_name = self.alias_reg(vn.get_register_name())
                    self.gen_printf(
                        f"{self.trace_pad}0x%x = {vn} ({cf.orange}{pretty_name}{cf.reset}){attr_str}\n",
                        res,
                    )
                return res

            return get_register
        elif vn.space is self.ram_space:
            raise NotImplementedError

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
                res = self.int_t(bswapped, space=self.ram_space)
                if self.trace:
                    self.gen_printf(f"{self.trace_pad}0x%x = {vn}\n", res)
                return res

            return get_ram
        else:
            raise NotImplementedError(vn.space.name)

    def setter_for_varnode(
        self,
        vn: Union[Varnode, Callable],
        sctx: Optional[LLVMSpaceContext] = None,
        op: Optional[PcodeOp] = None,
        force: bool = False,
    ) -> Callable[[IntVal], None]:
        if callable(vn):
            vn = vn()
        sctx = sctx or self.sctx_t()
        if vn.space is self.unique_space:

            def set_unique(v: IntVal) -> None:
                sctx.unique[vn.offset : vn.offset + vn.size] = v
                if self.trace:
                    self.gen_printf(f"{self.trace_pad}{vn} = 0x%x\n", v)

            return set_unique
        elif vn.space is self.const_space:
            raise ValueError("setting const?")
        elif vn.space is self.reg_space:
            rname = vn.get_register_name()
            ridx = self.reg_idx(rname)

            def set_register(v: IntVal) -> None:
                sctx.regs[vn.offset : vn.offset + vn.size] = v
                sctx.written_regs[vn.offset : vn.offset + vn.size] = v
                sctx.reg_gens[self.alias_reg(rname)] += 1
                if self.trace:
                    pretty_name = self.alias_reg(vn.get_register_name())
                    force_str = " [forced]" if force else ""
                    self.gen_printf(
                        f"{self.trace_pad}{vn} = 0x%x ({cf.orange}{pretty_name}{cf.reset}){force_str}\n",
                        v,
                    )
                if not force:
                    return
                if self.regs_lv.has_const_ops:
                    gep = self.regs_lv.gep([i32(0), i32(ridx)])
                else:
                    gep = self.bld.gep(
                        self.regs_lv,
                        [i32(0), i32(ridx)],
                        name=f"{self.alias_reg(rname)}_st_ptr",
                    )
                self.bld.store(v, gep)

            return set_register
        elif vn.space is self.ram_space:
            raise NotImplementedError

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
                if self.trace:
                    self.gen_printf(f"{self.trace_pad}{vn} = 0x%x\n", v)

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
            self.gen_bb_caller_call(tgt, self.sctx)
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
        self.gen_bb_caller_call(op.a())
        return None, True

    def handle_callother(self, op: PcodeOp):
        raise NotImplementedError

    def gen_bb_caller(self) -> ir.Function:
        fty = ir.FunctionType(void, [self.iptr, self.mem_t, self.regs_t.as_pointer()])
        f = ir.Function(self.m, ftype=fty, name="bb_caller_int")
        f.linkage = "internal"
        f.calling_convention = "tailcc"
        if self.inline:
            f.attributes.add("alwaysinline")
        bb = f.append_basic_block("entry")
        bb_addr = self.int_t(f.args[0])
        bb_addr.name = "bb_addr"
        self.mem_lv = self.int_t(f.args[1])
        self.mem_lv.name = "mem_ptr"
        self.mem_lv.attributes.add("nocapture")
        self.mem_lv.attributes.add("noalias")
        self.regs_lv = self.int_t(f.args[2])
        self.regs_lv.name = "regs_ptr"
        self.regs_lv.attributes.add("nocapture")
        self.regs_lv.attributes.add("noalias")
        self.bld.position_at_end(bb)
        text_start = self.int_t(self.iptr(self.exec_start))
        text_end = self.int_t(self.iptr(self.exec_end))
        ret_addr = self.int_t(self.iptr(self.ret_addr))

        # trace
        if self.trace:
            self.gen_printf("bb_caller() to 0x%x\n", bb_addr)

        # final return check
        is_final_return = ret_addr.cmp_op("==", bb_addr, name="is_final_return")
        with self.bld.if_then(is_final_return, likely=False):
            self.bld.ret_void()

        # bounds check
        not_under = bb_addr.cmp_op(">=", text_start, name="bb_addr_not_under")
        not_over = bb_addr.cmp_op("<", text_end, name="bb_addr_not_over")
        self.gen_assert(
            not_under & not_over,
            self.regs_lv,
            "bb_addr 0x%x is out of addr2bb range of 0x%x to 0x%x",
            bb_addr,
            text_start,
            text_end,
        )

        # access
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
        self.bld.call(
            bb_fptr,
            [self.mem_lv, self.regs_lv],
            tail=True,
            cconv="tailcc",
            name="bb_caller",
        )
        self.bld.ret_void()

        # external interface
        efty = ir.FunctionType(void, [self.iptr, self.mem_t, self.regs_t.as_pointer()])
        ef = ir.Function(self.m, ftype=efty, name="bb_caller")
        bb = ef.append_basic_block("entry")
        bb_addr = self.int_t(ef.args[0])
        bb_addr.name = "bb_addr"
        mem_ptr = self.int_t(ef.args[1])
        mem_ptr.name = "mem_ptr"
        regs_ptr = self.int_t(ef.args[2])
        regs_ptr.name = "regs_ptr"
        self.bld.position_at_end(bb)
        self.bld.call(f, [bb_addr, mem_ptr, regs_ptr], name="bb_caller_int")
        self.bld.ret_void()

        return f

    def gen_bb_caller_call(self, bb_addr: IntVal):
        self.write_dirtied_regs()
        self.write_diritied_mem()
        if bb_addr.is_const:
            call = self.bld.call(
                self.addr2bb[self.addr2bb_idx(bb_addr.conc.as_u)],
                [self.mem_lv, self.regs_lv],
                tail=True,
                name="bb_call_direct",
            )
        else:
            call = self.bld.call(
                self.bb_caller,
                [bb_addr, self.mem_lv, self.regs_lv],
                tail=True,
                name="bb_call",
            )
        self.bld.ret_void()

    def gen_instr_cb_call(self, bb: int, inst: Translation):
        self.bld.call(
            self.instr_cb,
            [
                self.iptr(bb),
                self.iptr(inst.address.offset),
                self.strpool[inst.asm_mnem],
                self.strpool[inst.asm_body],
            ],
            name="inst_cb_call",
        )

    def gen_op_cb_call(self, bb: int, op: PcodeOp):
        self.bld.call(
            self.op_cb,
            [
                self.iptr(bb),
                self.iptr(op.address),
                i32(op.seq.uniq),
                i32(op.opcode.value),
                self.strpool[str(op)],
            ],
            name="op_cb_call",
        )

    def printf_fmt_spec(self, ty: ir.IntType, signed: bool = False, x: bool = False):
        sz_fmt_map = {
            i1: "hh",
            i8: "hh",
            i16: "h",
            i32: "",
            i64: "l",
        }
        sz = sz_fmt_map[ty]
        if x:
            return f"%0{ty.width // 4}{sz}x"
        elif signed:
            return f"%{sz}d"
        else:
            return f"%{sz}u"

    def gen_printf(self, fmt: str, *args, name: Optional[str] = None) -> ir.CallInstr:
        args = [*args]
        # (%p)|(%d)|(%u)|(%x)|(%s)|(%%)
        match_num = 0
        idx_color = []

        def fix_fmt(match: re.Match):
            nonlocal match_num, args, idx_color
            arg = args[match_num]
            if match.group(1):
                ty_str = match.group(2)
                if ty_str == "p":
                    assert arg.type.is_pointer
                    if arg.is_const:
                        arg = self.int_t(arg.w.ptrtoint(self.iptr))
                    else:
                        arg = self.int_t(
                            self.bld.ptrtoint(arg, self.iptr, name="fmt_cast")
                        )
                    res = "0x" + self.printf_fmt_spec(arg.type, x=True)

                elif ty_str == "d":
                    assert not arg.type.is_pointer
                    res = self.printf_fmt_spec(arg.type, signed=True)
                elif ty_str == "u":
                    assert not arg.type.is_pointer
                    res = self.printf_fmt_spec(arg.type, signed=False)
                elif ty_str == "x":
                    assert not arg.type.is_pointer
                    res = self.printf_fmt_spec(arg.type, x=True)
                res = f"%s{res}{cf.reset}"
                idx_color.append(match_num)
            elif match.group(3):
                # 0x%x
                assert not arg.type.is_pointer
                res = self.printf_fmt_spec(arg.type, x=True)
                res = f"%s0x{res}{cf.reset}"
                idx_color.append(match_num)
            else:
                res = match.string
            args[match_num] = arg
            match_num += 1

            return res

        fmt = re.sub(PRINTF_FMT_RE, fix_fmt, fmt)

        arg_ins_idx = [idx + off for idx, off in zip(idx_color, range(len(idx_color)))]

        for arg_idx in arg_ins_idx:
            cond_v = args[arg_idx]
            color_v = cond_v.cmov(
                self.strpool[str(cf.palegreen)], self.strpool[str(cf.slateblue)]
            )
            args.insert(arg_idx, color_v)

        if isinstance(fmt, str):
            fmt = self.strpool[fmt]
        for i in range(len(args)):
            if isinstance(args[i], str):
                args[i] = self.strpool[args[i]]
            if isinstance(args[i], int):
                args[i] = i32(args[i])
        name = name or "printf"
        return self.bld.call(self.printf, [fmt, *args], name=name)

    def gen_cb_decls(self):
        instr_cb_t = ir.FunctionType(
            void, [self.iptr, self.iptr, i8.as_pointer(), i8.as_pointer()]
        )
        instr_cb = ir.Function(self.m, instr_cb_t, "instr_cb")
        op_cb_t = ir.FunctionType(
            void, [self.iptr, self.iptr, i32, i32, i8.as_pointer()]
        )
        op_cb = ir.Function(self.m, op_cb_t, "op_cb")
        return instr_cb, op_cb

    def gen_debugtrap(self):
        self.bld.call(self.debugtrap, [], name="debugtrap")

    def gen_utrans_panic_decl(self):
        untrans_panic_t = ir.FunctionType(void, [self.iptr])
        untrans_panic_t.args[0].name = "addr"
        return ir.Function(self.m, untrans_panic_t, "untrans_panic")

    def gen_printf_decl(self):
        printf_t = ir.FunctionType(i32, [i8.as_pointer()])
        printf_t.args[0].name = "fmt"
        printf_t.var_arg = True
        return ir.Function(self.m, printf_t, "printf")

    def gen_regs_dump_decls(self):
        dump_t = ir.FunctionType(void, [self.regs_t.as_pointer()])
        norm = ir.Function(self.m, dump_t, "regs_dump")
        aliased = ir.Function(self.m, dump_t, "regs_dump_alias")
        return norm, aliased

    def gen_regs_dump_call(self, regs_ptr: IntVal):
        self.bld.call(self.regs_dump, [regs_ptr], name="regs_dump_call")

    def gen_regs_dump_alias_call(self, regs_ptr: IntVal):
        self.bld.call(self.regs_dump_alias, [regs_ptr], name="regs_dump_alias_call")

    def gen_exit_decl(self):
        exit_t = ir.FunctionType(void, [i32])
        exit_t.args[0].name = "status"
        return ir.Function(self.m, exit_t, "exit")

    def gen_exit_call(self, status: int):
        self.bld.call(self.exit, [i32(status)], name="exit_call")

    def gen_assert(self, cond: IntVal, regs_ptr: IntVal, fmt: str, *args):
        if not self.assertions:
            return

        def bld_assert(f, *args, kind="ASSERTION"):
            self.gen_printf(
                f"\n{cf.red}{kind}:{cf.reset}\n\n{cf.deepPink}{f}{cf.reset}\n\n",
                *args,
                name="assert_printf",
            )
            self.gen_regs_dump_alias_call(regs_ptr)
            self.gen_printf("\n")
            self.gen_debugtrap()
            self.gen_exit_call(-42)

        if cond.is_const:
            if not cond.conc:
                raise AssertionError(
                    f"COMPILE-TIME ASSERTION: cond: {cond} fmt: {fmt} args: {' '.join(map(str, args))}"
                )
                bld_assert(fmt, *args, kind="COMPILE-TIME ASSERTION")
                return
        pred = cond.cmp_op("==", type(cond)(cond.type(0)), name="assert_cmp")
        with self.bld.if_then(pred, likely=False):
            bld_assert(fmt, *args)

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
        self.sctx = self.sctx_t()
        try:
            instrs = self.translate(addr, sctx=self.sctx)
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

        bb_list = list(self.bb_bbs.items())
        entry_bb = bb_list[0][1]
        exit_bb = bb_list[-1][1]
        self.mem_lv = self.int_t(f.args[0])
        self.mem_lv.name = "mem_ptr"
        self.mem_lv.attributes.add("nocapture")
        self.mem_lv.attributes.add("noalias")
        self.regs_lv = self.int_t(f.args[1])
        self.regs_lv.name = "regs_ptr"
        self.regs_lv.attributes.add("nocapture")
        self.regs_lv.attributes.add("noalias")
        self.bld.position_at_end(entry_bb)
        self.mem_base_lv = self.bld.ptrtoint(self.mem_lv, i64, name="mem_base_int")

        for instr in instrs:
            inst_addr = instr.address.offset
            self.dump(instr)

            for i, op in enumerate(instr.ops):
                assert i == op.seq.uniq
                self.bld.position_at_end(self.bb_bbs[(inst_addr, i)])
                if self.trace:
                    if i == 0:
                        self.gen_instr_cb_call(addr, instr)
                    self.gen_op_cb_call(addr, op)
                op_br_off, was_terminated = self.emu_pcodeop(op)
                if not was_terminated:
                    next_bb = self.bb_bbs[(inst_addr, i + 1)]
                    self.bld.branch(next_bb)

        with self.bld.goto_block(exit_bb):
            next_pc = self.int_t(
                self.iptr(instr.address.offset + instr.length + instr.length_delay),
                space=self.const_space,
            )
            self.gen_bb_caller_call(next_pc)

        return f

    def write_dirtied_regs(self):
        for vn_off, vn_sz in self.sctx.written_regs.keys():
            rname = self.ctx.get_register_name(self.reg_space, vn_off, vn_sz)
            vn = self.ctx.get_register(rname)
            reg_setter = self.setter_for_varnode(vn, force=True)
            dirty_val = self.sctx.written_regs[vn.offset : vn.offset + vn.size]
            reg_setter(dirty_val)
            dprint(f"name: {rname:4} vn: {str(vn):16} val: {dirty_val}")

    def write_diritied_mem(self):
        for virt_store_addr, v in self.sctx.written_mem.values():
            store_setter = self.setter_for_store(
                lambda: virt_store_addr, None, None, self.ram_space, self.sctx, True
            )
            store_setter(v)

    def lift(self):
        addrs = self.text_addrs if self.bb_override is None else self.bb_override
        for addr in self.text_addrs_sentinel:
            f = ir.Function(self.m, self.bb_t, f"bb_{addr:#010x}")
            f.linkage = "internal"
            f.calling_convention = "tailcc"
            self.mem_lv = self.int_t(f.args[0])
            self.mem_lv.name = "mem_ptr"
            self.mem_lv.attributes.add("nocapture")
            self.mem_lv.attributes.add("noalias")
            self.regs_lv = self.int_t(f.args[1])
            self.regs_lv.name = "regs_ptr"
            self.regs_lv.attributes.add("nocapture")
            self.regs_lv.attributes.add("noalias")
            if self.inline:
                f.attributes.add("alwaysinline")
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
        self.compile(opt=self.opt_level, asan=self.asan, msan=self.msan)

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
            p("} regs_t __attribute__((aligned(16)));")
            p()
            p('extern "C" void regs_dump(regs_t *regs);')
            p('extern "C" void regs_dump_alias(regs_t *regs);')
            p('extern "C" void regs_init(regs_t *regs);')
            p()

        with open(lifted_regs_cpp, "w") as f:
            p = lambda *args, **kwargs: print(*args, **kwargs, file=f)
            p('#include "lifted-regs.h"')
            p()
            p("#include <fmt/format.h>")
            p("#include <fmt/color.h>")
            p("using namespace fmt;")
            p()
            p("regs_t regs_dbginfo_dummy;")
            p()

            def gen_reg_dump_func(func_name: str, alias_func=lambda n: n):
                p(f"void {func_name}(regs_t *regs) {{")
                for rnames in chunked(reg_names, 4):
                    fmt_str = "    ".join(
                        [f"{alias_func(n):{max_name_len}s}: {{}}" for n in rnames]
                    )
                    fmt_args = [
                        f"format(fg(regs->{n} ? color::pale_green : color::slate_blue), "
                        + f'"{{:#0{self.ctx.get_register(n).size * 2 + 2}x}}", regs->{n})'
                        for n in rnames
                    ]
                    p(f'    print("{fmt_str}\\n", {", ".join(fmt_args)});')
                p("}")
                p()

            gen_reg_dump_func("regs_dump")
            gen_reg_dump_func("regs_dump_alias", alias_func=self.alias_reg)

    def compile(self, opt: str = "z", asan: bool = False, msan: bool = False):
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
            "-masm=intel",
            f"-O{opt}",
        ]
        LDFLAGS = []
        LIBS = ["-lfmt"]

        PRETTY_CXXFLAGS = [*CXXFLAGS, "-Oz", "-g0"]

        if asan:
            CXXFLAGS += ["-fsanitize=address", "-fno-omit-frame-pointer"]
            LDFLAGS += ["-fsanitize=address", "-fno-omit-frame-pointer"]
        if msan:
            CXXFLAGS += [
                "-fsanitize=memory",
                "-fsanitize-memory-track-origins=2",
                "-fno-omit-frame-pointer",
            ]
            LDFLAGS += [
                "-fsanitize=memory",
                "-fsanitize-memory-track-origins=2",
                "-fno-omit-frame-pointer",
            ]

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
