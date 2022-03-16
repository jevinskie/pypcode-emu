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
        return type(self)(f"{self} C+ {other}")

    def __str__(self) -> str:
        return f"C:{self.constant}"

    def __repr__(self) -> str:
        return f"Const({self.constant})"

    def __int__(self) -> int:
        return int(self.constant)


class VarVal:
    name: str

    def __init__(self, name: str):
        self.name = name

    def __str__(self) -> str:
        return f"V:{self.name}"

    def __repr__(self) -> str:
        return f"VarVal({self.name})"

    def __add__(self, other) -> VarVal:
        return type(self)(f"{self} VV+ {other}")


class IntVal(ObjectProxy):
    _self_concrete: Optional[int]

    def __init__(self, v):
        if isinstance(v, IntVal) and isinstance(v, ObjectProxy):
            v = v.__wrapped__
        super().__init__(v)
        try:
            self._self_concrete = int(v)
        except (ValueError, TypeError):
            self._self_concrete = None

    def __repr__(self) -> str:
        return f"IntVal({self})"

    @property
    def concrete(self) -> Optional[int]:
        return self._self_concrete

    @property
    def is_const(self):
        return isinstance(self, Const)

    def __add__(self, other: IntVal):
        if self.is_const and other.is_const:
            return type(self)(self.__wrapped__ + other)
        return type(self)(f"{self} IV+ {other}")


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

vunk = va + c42
ic(vunk)
ic(vunk.is_const)

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
try:
    ic(int(v43))
    assert False
except ValueError:
    pass
ic(v43.is_const)


v42_2 = IntVal(v42)
ic(v42_2)
