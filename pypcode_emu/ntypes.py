import operator
from typing import Type

import nativetypes as nt
from bidict import bidict

uint1 = nt.nint_type("uint1", 1, False)
int1 = nt.nint_type("int1", 1, True)

size2uintN = bidict({0: uint1, 1: nt.uint8, 2: nt.uint16, 4: nt.uint32, 8: nt.uint64})
size2intN = bidict({1: int1, 2: nt.int16, 4: nt.int32, 8: nt.int64})


def uintN(nbytes: int) -> Type[nt.nint]:
    return size2uintN[nbytes]


def intN(nbytes: int) -> Type[nt.nint]:
    return size2intN[nbytes]


def as_u(self: nt.nint):
    if self.v < 0:
        return nt.nint((1 << self.b) + self.v, self.b, False)
    return nt.nint(self.v, self.b, False)


nt.nint.as_u = property(as_u)


def as_s(self: nt.nint):
    if self.s:
        return self
    return nt.nint(self.v, self.b, True)


nt.nint.as_s = property(as_s)


def sext(self: nt.nint, nbits: int):
    return nt.nint(self.as_s.v, nbits, True)


nt.nint.sext = sext


def zext(self: nt.nint, nbits: int):
    return nt.nint(self.as_u.v, nbits, False)


nt.nint.zext = zext


def asr(self: nt.nint, nbits: int):
    return nt.nint((self.as_s >> nbits).v, self.b, True)


nt.nint.asr = asr


nt.nint.CMP_MAP = {
    ">": "gt",
    "<": "lt",
    "==": "eq",
    "!=": "ne",
    ">=": "ge",
    "<=": "le",
}


def cmp(self: nt.nint, cmp: str, other: nt.nint) -> nt.uint8:
    signed = cmp.startswith("s")
    if signed:
        a, b = self.as_s, other.as_s
    else:
        a, b = self.as_u, other.as_u
    cmp = cmp.lstrip("s")
    py_op_name = f"__{nt.nint.CMP_MAP[cmp]}__"
    op_func = getattr(operator, py_op_name)
    return nt.uint8(1 if op_func(a, b) else 0)


nt.nint.cmp = cmp

exported_attrs_names = list(
    filter(lambda n: not n.startswith("__") and not n.endswith("__"), dir(nt))
)
exported_attrs = [getattr(nt, n) for n in exported_attrs_names]
exported_attrs = [*exported_attrs, uint1, int1]
exported_attrs_names = [*exported_attrs_names, "uint1", "int1"]

for n, a in zip(exported_attrs_names, exported_attrs):
    globals()[n] = a

nint = nt.nint
uint8, int8 = nt.uint8, nt.int8
uint16, int16 = nt.uint16, nt.uint16
uint32, int32 = nt.uint32, nt.int32
uint64, int64 = nt.uint64, nt.int64

__all__ = tuple(exported_attrs_names)
