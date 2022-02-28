import argparse


def real_main(args):
    print(f"args: {args}")


def main() -> int:
    parser = argparse.ArgumentParser(description="ps3mfw")
    parser.add_argument("binary", help="Input binary file (binary/ELF)", metavar="BIN")
    real_main(parser.parse_args())
    return 0
