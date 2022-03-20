from llvmlite import ir


class CStringPool:
    _m: ir.Module
    _pool: dict[str, ir.GlobalVariable]
    _int_t: type

    def __init__(self, mod: ir.Module, int_t: type):
        self._m = mod
        self._pool = {}
        self._int_t = int_t

    def __getitem__(self, item) -> ir.GlobalVariable:
        if not isinstance(item, str):
            raise TypeError("must be str")
        if item in self._pool:
            return self._pool[item]
        buf = item.encode("utf-8") + b"\0"
        buf_ty = ir.ArrayType(ir.IntType(8), len(buf))
        gv = ir.GlobalVariable(self._m, buf_ty, name=f"pool_str_{len(self._pool)}")
        gv.global_constant = True
        gv.linkage = "internal"
        gv.initializer = ir.Constant(buf_ty, bytearray(buf))
        bc_gv = self._int_t(gv.bitcast(ir.IntType(8).as_pointer()))
        self._pool[item] = bc_gv
        return bc_gv
