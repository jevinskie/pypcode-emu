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
void setup_mem(size_t size = 0x1'0000'0000, void *preferred_addr = (void *)0x4000'0000'0000) {
    mem = (u8 *)mmap(preferred_addr, size, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE | (preferred_addr ? MAP_FIXED : 0), -1, 0);
    assert(mem);
}

void print_r3(void) {
    fmt::print("r3: {:#010x} r5: {:#010x}\n", regs.r3, regs.r5);
}

int main(int argc, const char **argv) {
    (void)argc;
    (void)argv;

    setup_mem();
    lifted_init();
    lifted_run();
    fmt::print("pc: {:#010x}\n", regs.pc);
    print_r3();

    double a = 243.0;
    double b = 42.0;
    double c = fpadd(a, b);
    fmt::print("fpadd({:f}, {:f}) = {:f}\n", a, b, c);

    return 0;
}
