#!/usr/bin/env python3
from __future__ import annotations

from typing import Optional

from icecream import ic
from wrapt import ObjectProxy


class Const:
    constant: str

    def __init__(self, val):
        self.constant = str(val)

    def __add__(self, other: Const) -> Const:
        assert isinstance(other, Const)
        return type(self)(f"{self} + {other}")

    def __str__(self) -> str:
        return self.constant

    def __repr__(self) -> str:
        return f"Const({self})"

    def __int__(self) -> Optional[int]:
        try:
            return int(self.constant)
        except ValueError:
            return None


class VarVal:
    name: str

    def __init__(self, name: str):
        self.name = name

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return f"VarVal({self})"


class IntVal(ObjectProxy):
    concrete: Optional[int]

    def __new__(cls, v):
        if isinstance(v, cls):
            return v
        return super().__new__(cls)

    def __init__(self, v):
        if isinstance(v, type(self)):
            return
        super().__init__(v)
        try:
            self.int_val = int(v)
        except TypeError:
            self.int_val = None

    def __repr__(self) -> str:
        return f"IntVal({self})"

    @property
    def is_const(self):
        return isinstance(self, Const)

    def __add__(self, other: IntVal):
        return type(self)(super(Const, self).__add__(other))


c42 = Const(42)
ic(c42)
c1 = Const(1)
ic(c1)
c43 = c1 + c42
ic(c43)

vva = VarVal("a")
ic(vva)
va = IntVal(vva)
ic(va)
ic(va.is_const)
try:
    int(va)
    assert False
except:
    pass


v42 = IntVal(c42)
ic(v42)
ic(int(v42))
ic(v42.is_const)
v1 = IntVal(c1)
ic(v1)
ic(int(v1))
ic(v1.is_const)
v43 = v1 + v42
ic(v43)
ic(int(v43))
ic(v43.is_const)
