#pragma once

#include <cstdint>

#include "lifted-regs.h"
#include "lifted-types.h"

constexpr int bytes_per_instr = 4;

using seg_t = struct {
    uptr addr;
    usz size;
    u8 ro;
    const u8 *data;
} __attribute__((packed));

extern "C" {

extern const u8 num_segs;
extern const seg_t segs[];

extern const uptr entry_point;

void bb_caller(uptr addr, u8 *mem, regs_t *regs);

void instr_cb(uptr bb, uptr pc, const char *asm_mnem, const char *asm_body);
void op_cb(uptr bb, uptr pc, uint32_t op_idx, uint32_t opc, const char *desc);
void untrans_panic(uptr pc);
}

void lifted_init(u8 *mem, regs_t *regs);
void lifted_run(u8 *mem, regs_t *regs);
