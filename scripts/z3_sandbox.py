#!/usr/bin/env python3

import nativetypes as ntypes
import z3


def scarry_ntypes(in1, in2):
    res = in1 + in2
    a = (in1 >> (in1.b - 1)) & 1
    b = (in2 >> (in2.b - 1)) & 1
    r = (res >> (res.b - 1)) & 1

    r ^= a
    a ^= b
    a ^= 1
    r &= a

    return r


def test_ntypes():
    nt_127 = ntypes.int8(127)
    nt_1 = ntypes.int8(1)
    nt_n1 = ntypes.int8(-1)
    nt_n128 = ntypes.int8(-128)

    r = scarry_ntypes(nt_127, nt_1)
    print(r)

    r = scarry_ntypes(nt_n128, nt_n1)
    print(r)

    r = scarry_ntypes(nt_n128, nt_1)
    print(r)


def scarry_z3(in1, in2):
    res = in1 + in2
    a = (in1 >> (in1.size() - 1)) & 1
    b = (in2 >> (in2.size() - 1)) & 1
    r = (res >> (res.size() - 1)) & 1

    r ^= a
    a ^= b
    a ^= 1
    r &= a

    return r


def test_z3():
    nt_127 = z3.BitVecVal(127, 8)
    nt_1 = z3.BitVecVal(1, 8)
    nt_n1 = z3.BitVecVal(-1, 8)
    nt_n128 = z3.BitVecVal(-128, 8)

    r = scarry_z3(nt_127, nt_1)
    print(r)
    print()
    print(z3.simplify(r))
    print("\n\n")

    r = scarry_z3(nt_n128, nt_n1)
    print(r)
    print()
    print(z3.simplify(r))
    print("\n\n")

    r = scarry_z3(nt_n128, nt_1)
    print(r)
    print()
    print(z3.simplify(r))
    print("\n\n")

    in1 = z3.BitVec("in1", 8)
    in2 = z3.BitVec("in2", 8)

    r = scarry_z3(in1, in2)
    print(r)
    print()
    print(z3.simplify(r))
    print("\n\n")


test_ntypes()
print("\n\n\n====================\n\n\n")
test_z3()
