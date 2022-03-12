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

static constexpr size_t addr2bb_idx(uptr addr) {
    return (addr - text_start) / bytes_per_instr;
}

void lifted_init() {
    load_segs();
}

void lifted_run() {
    fmt::print("lifted_run begin\n");
    auto idx = addr2bb_idx(entry_point);
    auto ep  = addr2bb[idx];
    ep();
    fmt::print("lifted_run end\n");
}

void untrans_panic(uptr pc) {
    fmt::print(stderr, "Tried to run untranslated BB at {:#010x}\n", pc);
    exit(-1);
}
