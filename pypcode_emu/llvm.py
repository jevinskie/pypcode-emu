from __future__ import annotations

import importlib.resources
import os
import platform
from typing import Optional, Union

import pretty_errors
from llvmlite import ir
from path import Path

from .elf import PF, PT
from .emu import ELFPCodeEmu
from .utils import gen_cmd

real_print = print
null_print = lambda *args, **kwargs: None

# dprint = null_print
dprint = real_print
iprint = real_print
eprint = real_print

CXX = gen_cmd(os.getenv("CXX", "clang++"))
LLVM_AS = gen_cmd(os.getenv("CXX", "llvm-as"))
LLVM_DIS = gen_cmd(os.getenv("CXX", "llvm-dis"))

i8 = ir.IntType(8)
i16 = ir.IntType(16)
i32 = ir.IntType(32)
i64 = ir.IntType(64)
void = ir.VoidType


class LLVMELFLifter(ELFPCodeEmu):
    exec_start: int
    exec_end: int
    exe_path = Path
    m: ir.Module
    addr2bb: list[ir.Function]
    bb_t: ir.FunctionType
    trans_panic: ir.GlobalVariable

    def __init__(
        self,
        elf_path: str,
        exe_path: str,
        entry: Optional[Union[str, int]] = None,
    ):
        super().__init__(elf_path, entry=entry)
        self.exe_path = Path(exe_path)
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

        self.m = self.get_init_mod()

        if self.bitness == 32:
            self.iptr = i32
            self.isz = i32
        else:
            self.iptr = i64
            self.isz = i64

        self.bb_t = ir.FunctionType(void, [])
        self.trans_panic = self.gen_trans_panic_decl()

        self.addr2bb = []
        for addr in range(self.exec_start, self.exec_end, 4):
            self.addr2bb.append(self.gen_trans_panic_func(addr))

        self.gen_text_addrs()

    def global_const(self, name: str, type: ir.Type, init) -> ir.GlobalVariable:
        gv = ir.GlobalVariable(self.m, type, name)
        gv.global_constant = True
        gv.initializer = ir.Constant(type, init)
        return gv

    def get_init_mod(self):
        m = ir.Module(name=self.exe_path.name + ".ll")
        triple = {
            ("x86_64", "Linux", "glibc"): "x86_64-linux-gnu",
        }.get((platform.machine(), platform.system(), platform.libc_ver()[0]))
        if triple:
            m.triple = triple
        return m

    def gen_trans_panic_decl(self):
        trans_panic_t = ir.FunctionType(void, [self.iptr])
        return ir.GlobalVariable(self.m, trans_panic_t, "trans_panic")

    def gen_trans_panic_func(self, addr: int) -> ir.Function:
        f = ir.Function(self.m, self.bb_t, f"bb_0x{addr:#010x}")
        bb = f.append_basic_block("entry")
        addr_c = ir.Constant(self.iptr, addr)
        builder = ir.IRBuilder(bb)
        builder.call(self.trans_panic, [addr_c])
        return f

    def gen_text_addrs(self):
        self.global_const("text_start", self.iptr, self.exec_start)
        self.global_const("text_end", self.iptr, self.exec_end)

    def gen_addr2bb(self):
        addr2bb_t = ir.ArrayType(self.bb_t.as_pointer(), len(self.addr2bb))
        addr2bb = ir.GlobalVariable(self.m, addr2bb_t, "addr2bb")
        addr2bb.global_constant = True

    def lift(self):
        self.lift_demo()
        self.gen_addr2bb()
        self.build()

    def lift_demo(self):
        # Create some useful types
        double = ir.DoubleType()
        fnty = ir.FunctionType(double, (double, double))

        # and declare a function named "fpadd" inside it
        func = ir.Function(self.m, fnty, name="fpadd")

        # Now implement the function
        block = func.append_basic_block(name="entry")
        builder = ir.IRBuilder(block)
        a, b = func.args
        a.name = "a"
        b.name = "b"
        result = builder.fadd(a, b, name="res")
        builder.ret(result)

        # Print the module IR
        print(self.m)

    def gen_lifted_regs_h(self, lifted_regs_h):
        with open(lifted_regs_h, "w") as f:
            p = lambda *args, **kwargs: print(*args, **kwargs, file=f)
            p("#pragma once")
            p()
            p("typedef struct {")
            reg_names = self.ctx.get_register_names()
            for rname in reg_names:
                reg = self.ctx.get_register(rname)
                p(f"    u{reg.size * 8} {rname};")
            p("} regs_t;")
            p()

    def write_ir(self, asm_out_path):
        open(asm_out_path, "w").write(str(self.m))

    @property
    def host_bitness(self):
        return {
            "32bit": 32,
            "64bit": 64,
        }[platform.architecture()[0]]

    def build(self):
        build_dir = Path("build")
        try:
            os.mkdir(build_dir)
        except FileExistsError:
            pass

        fmt_inc_dir = (
            importlib.resources.files(__package__) / "native" / "fmt" / "include"
        )

        lifted_regs_h = build_dir / "lifted-regs.h"
        self.gen_lifted_regs_h(lifted_regs_h)

        harness_cpp = importlib.resources.files(__package__) / "native" / "harness.cpp"
        harness_base = Path("build") / harness_cpp.name
        harness_o = harness_base + ".o"
        harness_ll = harness_base + ".ll"
        harness_s = harness_base + ".s"

        lifted_bc_ll = build_dir / "lifted-bc.ll"
        self.write_ir(lifted_bc_ll)
        lifted_bc_o = lifted_bc_ll + ".o"
        lifted_bc_s = lifted_bc_ll + ".s"
        lifted_bc_bc = lifted_bc_ll + ".bc"

        lifted_cpp = importlib.resources.files(__package__) / "native" / "lifted.cpp"
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
            build_dir,
            "-g",
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-Oz",
        ]
        LDFLAGS = []
        LIBS = ["-lfmt"]

        CXX(*CXXFLAGS, "-c", "-o", harness_o, harness_cpp)
        CXX(*CXXFLAGS, "-c", "-o", harness_s, "-S", harness_cpp, "-g0")
        CXX(*CXXFLAGS, "-c", "-o", harness_ll, "-S", "-emit-llvm", harness_cpp, "-g0")

        CXX(*CXXFLAGS, "-c", "-o", lifted_segs_o, lifted_segs_s)

        LLVM_AS("-o", lifted_bc_bc, lifted_bc_ll)
        LLVM_DIS("-o", lifted_bc_ll, lifted_bc_bc)
        os.remove(lifted_bc_bc)

        CXX(*CXXFLAGS, "-c", "-o", lifted_bc_o, lifted_bc_ll)
        CXX(*CXXFLAGS, "-c", "-o", lifted_bc_s, "-S", lifted_bc_ll, "-g0")

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
