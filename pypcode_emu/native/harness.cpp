#undef NDEBUG

#include <cassert>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fmt/format.h>

#include "lifted.h"

extern "C" double fpadd(double a, double b);

// 0x4000'0000'0000 makes asan happy
u8 *setup_mem(size_t size = 0x1'0000'0000, void *preferred_addr = (void *)0x4000'0000'0000) {
#if __has_feature(memory_sanitizer)
    preferred_addr = nullptr;
#endif
    u8 *mem = (u8 *)mmap(preferred_addr, size, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE | (preferred_addr ? MAP_FIXED : 0), -1, 0);
    assert(mem);
    assert((uintptr_t)mem != UINTPTR_MAX);
    return mem;
}

u8 *mem;
regs_t regs;

int main(int argc, const char **argv) {
    (void)argc;
    (void)argv;

    mem = setup_mem();
    lifted_init(mem, &regs);
    lifted_run(mem, &regs);
    fmt::print("pc: {:#010x} res: {:#010x}\n", regs.pc, regs.r3);

    return 0;
}
