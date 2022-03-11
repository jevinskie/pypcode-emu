#include <fmt/format.h>

#include "harness.h"

extern "C" double fpadd(double a, double b);

int main(int argc, const char **argv) {
    double a = 243.0;
    double b = 42.0;
    double c = fpadd(a, b);
    fmt::print("fpadd({:f}, {:f}) = {:f}\n", a, b, c);
    return 0;
}
