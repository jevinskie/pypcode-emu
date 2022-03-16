#!/usr/bin/env python3

from bidict import bidict
from pypcode import OpCode

p = lambda *args, **kwargs: print(*args, **kwargs)

opcodes = {}
for _, opc in OpCode.__members__.items():
    opcodes[opc.name] = opc.value
opcodes = bidict(sorted(opcodes.items(), key=lambda x: x[1]))

p("#pragma once")
p()
p("#include <cstdint>")
p()
p()

p("enum opc_t: uint8_t {")
for opc_name, opc_idx in opcodes.items():
    p(f"    {opc_name} = {opc_idx},")
p("};")
p()
p()
p("static const char *opc2str[] = {")
for i in range(max(opcodes.values()) + 1):
    if i in opcodes.values():
        p(f'    "{opcodes.inverse[i]}",')
    else:
        p("    nullptr,")
p("};")
p()
