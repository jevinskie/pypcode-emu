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
    regs_init();
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

void instr_cb(uptr bb, uptr pc, const char *desc) {
    fmt::print("BB: {:#010x} PC: {:#010x} {:s}\n", bb, pc, desc);
}

void op_cb(uptr bb, uptr pc, uint32_t op_idx, uint32_t opc, const char *desc) {
    fmt::print("BB: {:#010x} PC: {:#010x} op idx: {:2d} opc: {:s} desc: {:s}\n", bb, pc, op_idx,
               opc2str[opc], desc);
}
