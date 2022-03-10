import argparse

from ..llvm import LLVMELFLifter


def real_main(args):
    lifter = LLVMELFLifter(args.elf, args.bitcode, args.entry)
    lifter.lift()


def main() -> int:
    parser = argparse.ArgumentParser(description="pypcode-emu")
    parser.add_argument("elf", help="Input ELF file", metavar="ELF")
    parser.add_argument("bitcode", help="Output bitcode file", metavar="BC")
    parser.add_argument("-e", "--entry", help="Entry point", metavar="ENTRY")
    args = parser.parse_args()
    real_main(args)
    return 0


if __name__ == "__main__":
    main()
