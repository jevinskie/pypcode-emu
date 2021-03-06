import argparse

from pypcode_emu.llvm import LLVMELFLifter


def real_main(args):
    lifter = LLVMELFLifter(
        args.elf,
        args.exe,
        entry=args.entry,
        bb_override=args.bb_addr,
        asan=args.asan,
        msan=args.msan,
        opt=args.O,
        trace=args.trace,
        arg0=args.arg0,
        inline=args.inline,
        assertions=args.assertions,
    )
    lifter.lift()
    # try:
    #     lifter.lift()
    # except Exception as e:
    #     print("IR Module:")
    #     print(str(lifter.m))
    #     print(f"lifting error: {e}")


def main() -> int:
    parser = argparse.ArgumentParser(description="pypcode-emu")
    parser.add_argument("elf", help="Input ELF file", metavar="ELF")
    parser.add_argument("exe", help="Output executable", metavar="EXE")
    parser.add_argument("-e", "--entry", help="Entry point", metavar="ENTRY")
    parser.add_argument(
        "-0",
        "--arg0",
        type=lambda n: int(n, 0),
        default=0,
        help="Argument 0",
        metavar="ARG0",
    )
    parser.add_argument("-t", "--trace", help="Enable tracing", action="store_true")
    parser.add_argument("-i", "--inline", help="Enable inlining", action="store_true")
    parser.add_argument(
        "-A",
        "--no-assert",
        dest="assertions",
        help="Disable Assertions",
        action="store_false",
    )
    parser.add_argument("--asan", help="Enable Address Sanitizer", action="store_true")
    parser.add_argument("--msan", help="Enable Memory Sanitizer", action="store_true")
    parser.add_argument(
        "-O", default="z", help="Optimization level", metavar="OPT_LEVEL"
    )
    parser.add_argument(
        "-b",
        "--bb-addr",
        help="Basic block address override",
        type=lambda n: int(n, 0),
        action="append",
        metavar="BB",
    )
    args = parser.parse_args()
    real_main(args)
    return 0


if __name__ == "__main__":
    main()
