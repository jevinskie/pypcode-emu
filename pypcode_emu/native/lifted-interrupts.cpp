#include <fmt/color.h>
#include <fmt/format.h>
using namespace fmt;

#include "lifted.h"

void software_interrupt(uptr bb, uptr pc, u8 *mem, regs_t *regs, usz arg) {
    print("{} ]> {} SWI arg: {:#010x}\n", format(fg(color::fuchsia), "{:#010x}", bb),
          format(fg(color::lawn_green), "{:#010x}", pc), arg);
}
