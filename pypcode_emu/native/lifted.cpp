#undef NDEBUG

#include <cassert>
#include <cstdio>
#include <cstdlib>

#include <fmt/format.h>

#include "lifted.h"
#include "pcode-opcodes.h"

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

void instr_cb(uptr bb, uptr pc) {
    fmt::print("BB: {:#010x} PC: {:#010x}\n", bb, pc);
}

void op_cb(uptr bb, uptr pc, uint32_t op_idx, uint32_t opc) {
    fmt::print("BB: {:#010x} PC: {:#010x} op idx: {:2d} opc: {:s} r5: {:#010x}\n", bb, pc, op_idx,
               opc2str[opc], regs.r5);
}
