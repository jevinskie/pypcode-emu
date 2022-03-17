from typing import Type

from bidict import bidict
from nativetypes import *

size2uintN = bidict({1: uint8, 2: uint16, 4: uint32, 8: uint64})
size2intN = bidict({1: int8, 2: int16, 4: int32, 8: int64})

del bidict


def uintN(nbytes: int) -> nint:
    return size2uintN[nbytes]


def intN(nbytes: int) -> nint:
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
    return nint(self.as_s, nbits, True)


nint.sext = sext

del sext


def zext(self: nint, nbits: int):
    return nint(self.as_u, nbits, False)


nint.zext = zext

del zext

del Type
