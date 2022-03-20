import operator
from typing import Type

from bidict import bidict
from nativetypes import *

uint1 = nint_type("uint1", 1, False)
int1 = nint_type("int1", 1, True)

size2uintN = bidict({0: uint1, 1: uint8, 2: uint16, 4: uint32, 8: uint64})
size2intN = bidict({1: int1, 2: int16, 4: int32, 8: int64})


def uintN(nbytes: int) -> Type[nint]:
    return size2uintN[nbytes]


def intN(nbytes: int) -> Type[nint]:
    return size2intN[nbytes]


def as_u(self: nint):
    if self.v < 0:
        return nint((1 << self.b) + self.v, self.b, False)
    return nint(self.v, self.b, False)


nint.as_u = property(as_u)
del as_u


def as_s(self: nint):
    if self.s:
        return self
    return nint(self.v, self.b, True)


nint.as_s = property(as_s)
del as_s


def sext(self: nint, nbits: int):
    return nint(self.as_s.v, nbits, True)


nint.sext = sext
del sext


def zext(self: nint, nbits: int):
    return nint(self.as_u.v, nbits, False)


nint.zext = zext
del zext


def asr(self: nint, nbits: int):
    return nint((self.as_s >> nbits).v, self.b, True)


nint.asr = asr
del asr


CMP_MAP = {
    ">": "gt",
    "<": "lt",
    "==": "eq",
    "!=": "ne",
    ">=": "ge",
    "<=": "le",
}


def cmp(self: nint, cmp: str, other: nint) -> uint8:
    signed = cmp.startswith("s")
    if signed:
        a, b = self.as_s, other.as_s
    else:
        a, b = self.as_u, other.as_u
    cmp = cmp.lstrip("s")
    py_op_name = f"__{CMP_MAP[cmp]}__"
    op_func = getattr(operator, py_op_name)
    return uint8(1 if op_func(a, b) else 0)


nint.CMP_MAP = CMP_MAP
nint.cmp = cmp
del CMP_MAP, cmp

del Type, bidict, operator
