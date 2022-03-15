#undef NDEBUG

#include <cassert>
#include <cstdio>
#include <cstdlib>

#include <fmt/format.h>

#include "lifted.h"

u8 *mem;

static void load_segs() {
    for (int i = 0; i < num_segs; ++i) {
        memcpy(mem + segs[i].addr, segs[i].data, segs[i].size);
    }
}

void lifted_init() {
    load_segs();
}

void lifted_run() {
    fmt::print("lifted_run begin\n");
    bb_caller(entry_point);
    fmt::print("lifted_run end\n");
}

void untrans_panic(uptr pc) {
    fmt::print(stderr, "Tried to run untranslated BB at {:#010x}\n", pc);
    exit(-1);
}

void instr_cb(uptr pc) {
    fmt::print("PC: {:#010x}\n", pc);
}

void op_cb(uptr pc, uint32_t op_idx, uint32_t opc) {
    fmt::print("PC: {:#010x} op idx: {:2d} opc: {:3d}\n", pc, op_idx, opc);
}
