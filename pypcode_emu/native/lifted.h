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

#include "lifted-regs.h"

extern "C" u8 *mem;

extern "C" regs_t regs;

using bb_t = void (*)(void);

extern "C" bb_t *addr2bb;
