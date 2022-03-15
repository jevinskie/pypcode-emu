#pragma once

#include <cstdint>

using u8   = uint8_t;
using s8   = int8_t;
using u16  = uint16_t;
using s16  = int16_t;
using u32  = uint32_t;
using s32  = int32_t;
using u64  = uint64_t;
using s64  = int64_t;
using uptr = u32;
using sptr = s32;
using usz  = uptr;
using ssz  = sptr;

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

void instr_cb(uptr pc);
void op_cb(uptr pc, uint32_t op_idx, uint32_t opc);
void untrans_panic(uptr pc);
}

void lifted_init();
void lifted_run();
