from __future__ import annotations

import importlib.resources
import os
import platform
from pathlib import Path
from typing import Optional, Union

from llvmlite import ir

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


class LLVMELFLifter(ELFPCodeEmu):
    exec_start: int
    exec_end: int
    bc_path: Path
    exe_path = Path
    m: ir.Module
    addr2bb: dict[int, ir.Function]

    def __init__(
        self,
        elf_path: str,
        bc_path: str,
        exe_path: str,
        entry: Optional[Union[str, int]] = None,
    ):
        super().__init__(elf_path, entry=entry)
        self.bc_path = Path(bc_path)
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
        self.m = self._get_init_mod()
        self.addr2bb = {}
        self._generate_lifted_regs_h()

    def _get_init_mod(self):
        m = ir.Module(name=Path(self.bc_path).name)
        triple = {
            ("x86_64", "Linux", "glibc"): "x86_64-linux-gnu",
        }.get((platform.machine(), platform.system(), platform.libc_ver()[0]))
        if triple:
            m.triple = triple
        return m

    def _generate_lifted_regs_h(self):
        lifted_regs_h = (
            importlib.resources.files(__package__) / "native" / "lifted-regs.h"
        )
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

    def write_ir(self):
        open(self.bc_path, "w").write(str(self.m))

    def build(self):
        harness_cpp = importlib.resources.files(__package__) / "native" / "harness.cpp"
        fmt_inc_dir = (
            importlib.resources.files(__package__) / "native" / "fmt" / "include"
        )
        harness_o = harness_cpp.name + ".o"
        bc_o = self.bc_path.name + ".o"
        bc_s = self.bc_path.name + ".s"
        bc_bc = self.bc_path.name + ".bc"
        lifted_cpp = importlib.resources.files(__package__) / "native" / "lifted.cpp"
        lifted_o = lifted_cpp.name + ".o"
        lifted_ll = lifted_cpp.name + ".ll"

        lifted_s = lifted_cpp.name + ".s"
        CXXFLAGS = ["-I", fmt_inc_dir, "-g", "-std=c++20", "-Wall", "-Wextra", "-Oz"]
        LDFLAGS = []
        LIBS = ["-lfmt"]

        CXX(*CXXFLAGS, "-c", "-o", harness_o, harness_cpp)

        LLVM_AS("-o", bc_bc, self.bc_path)
        LLVM_DIS("-o", self.bc_path, bc_bc)
        os.remove(bc_bc)

        CXX(*CXXFLAGS, "-c", "-o", bc_o, self.bc_path)
        CXX(*CXXFLAGS, "-c", "-o", bc_s, "-S", self.bc_path, "-g0")

        CXX(*CXXFLAGS, "-c", "-o", lifted_o, lifted_cpp)
        CXX(*CXXFLAGS, "-c", "-o", lifted_s, "-S", lifted_cpp, "-g0")
        CXX(*CXXFLAGS, "-c", "-o", lifted_ll, "-S", "-emit-llvm", lifted_cpp, "-g0")

        CXX(*LDFLAGS, "-o", self.exe_path, bc_o, harness_o, lifted_o, *LIBS)

    def lift(self):
        self.gen_segs()
        self.lift_demo()
        self.write_ir()
        self.build()

    def gen_segs(self):
        num_segs = ir.GlobalVariable(self.m, i8, "num_segs")
        num_segs.global_constant = True
        num_segs.initializer = ir.Constant(i8, len(self.segments))

        segs = ir.GlobalVariable(self.m, i8, "segs")
        segs.global_constant = True
        segs.initializer = ir.Constant(i8, len(self.segments))
        # for seg in self.segments:

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
