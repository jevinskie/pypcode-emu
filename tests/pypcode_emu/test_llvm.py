from pypcode_emu.llvm import *


class TestIntVal:
    def test_intval(self):
        z0_16 = IntVal(i16(0))
        z0_32 = z0_16.sext(4)

        z1_16 = IntVal(i16(0))
        z1_32 = z1_16.sext(4)

        print(z0_32)
        print(z1_32)
        eq = z0_32 == z1_32
        print(eq)
        print(z0_32.exprs)
        print(z1_32.exprs)
