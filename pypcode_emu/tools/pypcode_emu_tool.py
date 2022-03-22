import argparse

from path import Path

from pypcode_emu.elf import BinaryError
from pypcode_emu.emu import ELFPCodeEmu, RawBinaryPCodeEmu


def real_main(args):
    try:
        emu = ELFPCodeEmu(args.binary, args.entry, arg0=args.arg0)
    except BinaryError:
        args.entry = int(args.entry, 0)
        if args.base is None:
            args.base = args.entry
        emu = RawBinaryPCodeEmu(
            args.spec, args.binary, args.base, args.entry, arg0=args.arg0
        )
        bin_sz = Path(args.binary).size
        if args.max_bytes == 0:
            args.max_bytes = bin_sz
        assert args.max_bytes <= bin_sz
    instr = emu.translate(
        emu.entry,
        max_inst=args.max_inst,
        max_bytes=args.max_bytes,
        bb_nonlinear_terminating=args.bb_terminating,
    )
    emu.dump(instr, pretty=args.pretty, raw=args.raw)


def main() -> int:
    parser = argparse.ArgumentParser(description="pypcode-emu")
    parser.add_argument("binary", help="Input binary file (binary/ELF)", metavar="BIN")
    parser.add_argument("-e", "--entry", help="Entry point", metavar="ENTRY")
    parser.add_argument(
        "-a", "--arg0", help="arg0", default=0, type=lambda s: int(s, 0), metavar="ARG0"
    )
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
        "-P",
        "--no-pretty",
        dest="pretty",
        help="Disable P-Code pretty printing",
        action="store_false",
    )
    parser.add_argument(
        "-R",
        "--no-raw",
        dest="raw",
        help="Disable P-Code raw printing",
        action="store_false",
    )
    parser.add_argument(
        "-b", "--base", type=lambda x: int(x, 0), help="Base address", metavar="BASE"
    )
    args = parser.parse_args()
    real_main(args)
    return 0


if __name__ == "__main__":
    main()
