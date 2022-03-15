#!/usr/bin/env python3

from llvmlite import ir

i1 = ir.IntType(1)
i8 = ir.IntType(8)
i16 = ir.IntType(16)
i32 = ir.IntType(32)
i64 = ir.IntType(64)
void = ir.VoidType()

m = ir.Module()
fty = ir.FunctionType(void, [i32, i32, i32])
f = ir.Function(m, fty, "cmov_test")

entry = f.append_basic_block("entry")
bld = ir.IRBuilder(entry)

cond_v = f.args[0]
cond_v.name = "cond"
true_v = f.args[1]
true_v.name = "true_val"
false_v = f.args[2]
false_v.name = "false_val"

bool_v = bld.icmp_unsigned("==", cond_v, cond_v.type(0), name="cmov_cond")
# cur_bb = bld.basic_block
# with bld.if_else(bool_v) as (then, otherwise):
#     with then:
#         true_bb = bld.basic_block
#     with otherwise:
#         false_bb = bld.basic_block
bld.select(bool_v, true_v, false_v, name="cmov_val")

print(m)
