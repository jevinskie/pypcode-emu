#undef NDEBUG

#include <cassert>
#include <cstdio>
#include <cstdlib>

#include <fmt/color.h>
#include <fmt/format.h>
using namespace fmt;

#include "lifted.h"
#include "pcode-opcodes.h"

static void load_segs(u8 *mem) {
    for (int i = 0; i < num_segs; ++i) {
        memcpy(mem + segs[i].addr, segs[i].data, segs[i].size);
    }
}

void lifted_init(u8 *mem, regs_t *regs) {
    load_segs(mem);
    regs_init(regs);
}

void lifted_run(u8 *mem, regs_t *regs) {
    print("lifted_run begin\n");
    bb_caller(entry_point, mem, regs);
    print("lifted_run end\n");
}

void untrans_panic(uptr pc) {
    print(stderr, "Tried to run untranslated BB at {}\n", format(fg(color::red), "{:#010x}", pc));
    exit(-1);
}

void instr_cb(uptr bb, uptr pc, const char *asm_mnem, const char *asm_body) {
    print("{} ]> {}        {:s} {:s}\n", format(fg(color::fuchsia), "{:#010x}", bb),
          format(fg(color::lawn_green), "{:#010x}", pc), asm_mnem, asm_body);
}

void op_cb(uptr bb, uptr pc, uint32_t op_idx, uint32_t opc, const char *desc) {
    print("{} ]> {} / {}            {:s}\n", format(fg(color::fuchsia), "{:#010x}", bb),
          format(fg(color::lawn_green), "{:#010x}", pc), format(fg(color::red), "{:2d}", op_idx),
          desc);
}

// https://gist.github.com/ditServices/ba3ebabab499afd1056daf828225247f

using rgb_t = struct { double r, g, b; };

using hsv_t = struct { double h, s, v; };

rgb_t hsv_to_rgb(hsv_t hsv) {
    if (hsv.s == 0.0) {
        return {hsv.v, hsv.v, hsv.v};
    }
    int i    = hsv.h * 6.0;
    double f = (hsv.h * 6.0) - i;
    double p = hsv.v * (1.0 - hsv.s);
    double q = hsv.v * (1.0 - hsv.s * f);
    double t = hsv.v * (1.0 - hsv.s * (1.0 - f));

    rgb_t rgb = {0, 0, 0};

    // clang-format off
    switch (i % 6) {
        case 0: rgb.r = hsv.v; rgb.g = t; rgb.b = p; break;
        case 1: rgb.r = q; rgb.g = hsv.v; rgb.b = p; break;
        case 2: rgb.r = p; rgb.g = hsv.v; rgb.b = t; break;
        case 3: rgb.r = p; rgb.g = q; rgb.b = hsv.v; break;
        case 4: rgb.r = t; rgb.g = p; rgb.b = hsv.v; break;
        case 5: rgb.r = hsv.v; rgb.g = p; rgb.b = q; break;
    }
    // clang-format on
    return rgb;
}