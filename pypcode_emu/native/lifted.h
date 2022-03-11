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
using ssz  = iptr;

using bb_t = void (*)(void);

#include "lifted-regs.h"

using seg_t = struct {
    uptr addr;
    usz size;
    const u8 *data;
};

extern "C" {
u8 *mem;

regs_t regs;

const u8 num_segs;
const seg_t *segs;

bb_t *addr2bb;

void untran_panic(uptr pc);
}

void lifted_init();
void lifted_run();