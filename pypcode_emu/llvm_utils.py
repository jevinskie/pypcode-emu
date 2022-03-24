import re

from llvmlite import ir

DESCR_WORDS_RE = re.compile("(0[xX][0-9a-fA-F]+)|([A-Z_-]{3,})|([a-z]{3,})")


class CStringPool:
    _m: ir.Module
    _pool: dict[str, ir.GlobalVariable]
    _int_t: type

    def __init__(self, mod: ir.Module, int_t: type):
        self._m = mod
        self._pool = {}
        self._int_t = int_t

    def get_name(self, cstr: str) -> str:
        # get rid of matches with group 0 (hex literals that confuse alpha matching)
        matches = filter(
            lambda m: m[0] is None, [m.groups() for m in DESCR_WORDS_RE.finditer(cstr)]
        )
        matches = [m[1] or m[2] for m in matches]
        return f"cstr_{len(self._pool)}_{'_'.join(matches)}"

    def __getitem__(self, item) -> ir.GlobalVariable:
        if not isinstance(item, str):
            raise TypeError("must be str")
        if item in self._pool:
            return self._pool[item]
        buf = item.encode("utf-8") + b"\0"
        buf_ty = ir.ArrayType(ir.IntType(8), len(buf))
        gv = ir.GlobalVariable(self._m, buf_ty, name=self.get_name(item))
        gv.global_constant = True
        gv.linkage = "internal"
        gv.initializer = ir.Constant(buf_ty, bytearray(buf))
        bc_gv = gv.bitcast(ir.IntType(8).as_pointer())
        bc_gv = self._int_t(bc_gv)
        self._pool[item] = bc_gv
        return bc_gv
