#!/usr/bin/env python3

from pypcode_emu.llvm import *


class StubLLVMELFLifter:
    m: ir.Module
    f: ir.Function
    bld: ir.IRBuilder

    def __init__(self):
        self.m = ir.Module(name=__file__)
        fty = ir.FunctionType(void, [])
        self.f = ir.Function(self.m, fty, "test_func")
        entry_bb = self.f.append_basic_block("entry")
        self.bld = ir.IRBuilder(entry_bb)


class TestIntVal:
    def test_intval(self):
        ctx = StubLLVMELFLifter()
        int_t = IntVal.class_with_lifter(ctx)
        z0_16 = int_t(i16(0))
        z0_32 = z0_16.sext(4)
        r5_0 = int_t(ir.Argument(ctx.f, i32, "r5_0"))
        r5_0_p_z0_32 = r5_0 + z0_32

        z1_16 = int_t(i16(0))
        z1_32 = z1_16.sext(4)
        r5_1 = int_t(ir.Argument(ctx.f, i32, "r5_1"))
        r5_1_p_z1_32 = r5_1 + z1_32

        print(z0_32)
        print(r5_0)
        print(r5_0_p_z0_32)

        print(z1_32)
        print(r5_1)
        print(r5_1_p_z1_32)

        eq = r5_1_p_z1_32.comp_time_eq(r5_0_p_z0_32)
        print(eq)

        r5_0_p_z1_32 = r5_0 + z1_32
        print(r5_0_p_z1_32)
        print(r5_0_p_z0_32.exprs)
        print(r5_0_p_z1_32.exprs)
        eq2 = r5_0_p_z1_32.comp_time_eq(r5_0_p_z0_32)
        print(eq2)

        # print(z0_32.exprs)
        # print(r5_0.exprs)
        # print(r5_0_p_z0_32.exprs)

        # print(z1_32.exprs)
        # print(r5_1.exprs)
        # print(r5_1_p_z1_32.exprs)

        print()


if __name__ == "__main__":
    tc = TestIntVal()
    tc.test_intval()
