#pragma once

#include <cstdint>

#include "lifted-types.h"

constexpr int bytes_per_instr = 4;

#include "lifted-regs.h"

using seg_t = struct {
    uptr addr;
    usz size;
    u8 ro;
    const u8 *data;
} __attribute__((packed));

extern "C" {
extern u8 *mem;

extern regs_t regs;

extern const u8 num_segs;
extern const seg_t segs[];

extern const uptr entry_point;

void bb_caller(uptr addr);

void instr_cb(uptr bb, uptr pc);
void op_cb(uptr bb, uptr pc, uint32_t op_idx, uint32_t opc);
void untrans_panic(uptr pc);
}

void lifted_init();
void lifted_run();
