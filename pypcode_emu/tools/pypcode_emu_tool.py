import argparse

from ..elf import BinaryError
from ..emu import ELFPCodeEmu, PCodeEmu


def real_main(args):
    try:
        emu = ELFPCodeEmu(args.binary, args.entry)
    except BinaryError:
        emu = PCodeEmu(args.spec, args.binary, args.base, int(args.entry, 0))
    instr = emu.translate(
        emu.entry,
        max_inst=args.max_inst,
        max_bytes=args.max_bytes,
        bb_terminating=args.bb_terminating,
    )
    emu.dump(instr)


def main() -> int:
    parser = argparse.ArgumentParser(description="pypcode-emu")
    parser.add_argument("binary", help="Input binary file (binary/ELF)", metavar="BIN")
    parser.add_argument("-e", "--entry", help="Entry point", metavar="ENTRY")
    parser.add_argument("-s", "--spec", help="Specification", metavar="SPEC")
    parser.add_argument(
        "-m",
        "--max-bytes",
        default=0,
        type=lambda x: int(x, 0),
        help="Maximum number of bytes to translate",
        metavar="MAXBYTES",
    )
    parser.add_argument(
        "-M",
        "--max-inst",
        default=0,
        type=lambda x: int(x, 0),
        help="Maximum number of instructions to translate",
        metavar="MAXINST",
    )
    parser.add_argument(
        "--bb-terminating",
        type=bool,
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Don't stop translation at end of BB",
        metavar="BB",
    )
    parser.add_argument(
        "-b", "--base", type=lambda x: int(x, 0), help="Base address", metavar="BASE"
    )
    args = parser.parse_args()
    real_main(args)
    return 0


if __name__ == "__main__":
    main()
