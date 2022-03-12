import argparse

from pypcode_emu.llvm import LLVMELFLifter


def real_main(args):
    lifter = LLVMELFLifter(args.elf, args.exe, args.entry)
    lifter.lift()


def main() -> int:
    parser = argparse.ArgumentParser(description="pypcode-emu")
    parser.add_argument("elf", help="Input ELF file", metavar="ELF")
    parser.add_argument("exe", help="Output executable", metavar="EXE")
    parser.add_argument("-e", "--entry", help="Entry point", metavar="ENTRY")
    args = parser.parse_args()
    real_main(args)
    return 0


if __name__ == "__main__":
    main()
