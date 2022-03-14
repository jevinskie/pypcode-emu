#!/usr/bin/env python3

import z3

import pypcode_emu.ntypes as ntypes


def scarry(in1, in2):
    res = in1 + in2
    a = (in1 >> (in1.b - 1)) & 1
    b = (in2 >> (in2.b - 1)) & 1
    r = (res >> (res.b - 1)) & 1

    r ^= a
    a ^= b
    a ^= 1
    r &= a

    return r


nt_127 = ntypes.int8(127)
nt_1 = ntypes.int8(1)
nt_n1 = ntypes.int8(-1)
nt_n128 = ntypes.int8(-128)

r = scarry(nt_127, nt_1)
print(r)

r = scarry(nt_n128, nt_n1)
print(r)

r = scarry(nt_n128, nt_1)
print(r)
