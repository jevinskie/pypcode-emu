#!/usr/bin/env python3
from __future__ import annotations

from abc import (
    ABC,
    abstractclassmethod,
    abstractmethod,
    abstractproperty,
    abstractstaticmethod,
)
from typing import ClassVar, NewType

from llvmlite import ir
from wrapt import ObjectProxy

i8 = ir.IntType(8)
i16 = ir.IntType(16)
i32 = ir.IntType(32)
i64 = ir.IntType(64)
void = ir.VoidType()


class IntValBase:
    bld: ClassVar[ir.IRBuilder]

    @property
    def size(self):
        print(f"size: {self}")
        return {i8: 1, i16: 2, i32: 4, i64: 8}[self.type]

    # these are dummy since, unlike python, everything is 2's compliment
    def sext(self) -> IntVal:
        print(f"sext: {self}")
        return self

    def s2u(self) -> IntVal:
        print(f"s2u: {self}")
        return self


class IntVal(ObjectProxy, IntValBase):
    def __new__(cls, wrapped):
        if isinstance(wrapped, IntValBase):
            return wrapped
        return super().__new__(cls)

    def __init__(self, wrapped):
        if isinstance(wrapped, IntValBase):
            return
        super().__init__(wrapped)

    @classmethod
    def class_with_builder(cls, builder: ir.IRBuilder) -> type:
        return type("BoundIntVal", (IntVal,), {"bld": builder})


m = ir.Module()
fty = ir.FunctionType(void, [])
f = ir.Function(m, fty, "dummy")
bld = ir.IRBuilder(f.append_basic_block("entry"))

BIntVal = IntVal.class_with_builder(bld)

iconst = i32(243)
print(f"iconst: {iconst} type(iconst): {type(iconst)} iconst.type: {iconst.type}")
print(f"isinstance(iconst, ir.Value): {isinstance(iconst, ir.Value)}")
print(f"type(iconst).mro(): {type(iconst).mro()}")

i = BIntVal(iconst)

print(i.size)

print(f"i: {i} type(i): {type(i)} i.type: {i.type}")
print(f"isinstance(i, ir.Value): {isinstance(i, ir.Value)}")
print(f"type(i).mro(): {type(i).mro()}")
print(i.s2u())

bld.ret_void()

print(str(m))
