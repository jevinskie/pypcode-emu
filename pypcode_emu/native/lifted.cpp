#undef NDEBUG

#include <cassert>
#include <cstdio>
#include <cstdlib>

#include <fmt/format.h>

#include "lifted.h"

static void load_segs() {
    for (int i = 0; i < num_segs; ++i) {
        auto &seg = &segs[i];
        memcpy(mem + seg.addr, seg.data, seg.size);
    }
}

void lifted_init() {
    load_segs();
}

void lifted_run() {
    fmt::print("lifted_run begin\n");
    fmt::print("lifted_run end\n");
}

void untran_panic(uptr pc) {
    fmt::print(stderr, "Tried to run untranslated BB at {#010x}", pc);
    exit(-1);
}
