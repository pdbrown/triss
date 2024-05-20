import sys
import argparse

from . import core

def main():
    parser = argparse.ArgumentParser(
        prog="trivial_secret_sharing",
        description="""Trivial secret sharing utility.
    Split input into M-of-N shares or recover input from a set of shares.""")
    sp = parser.add_subparsers(dest='command', required=True)
    s = sp.add_parser('split', help="Split secret into shares.")
    s.add_argument('n', type=int, metavar='N',
                   help="number of shares")
    s.add_argument('out_dir', type=str, metavar='DIR',
                   help="destination directory path")
    s.add_argument('-m', type=int,
                   help="number of required shares for M-of-N split")
    s.add_argument('-i', type=str, required=False,
                   metavar='IN_FILE',
                   help="path to input file, read from stdin if omitted")
    s.add_argument('-f', required=False, choices=['DATA', 'QRCODE'],
                   default=core.DEFAULT_FORMAT,
                   help="output file format, defaults to " + \
                         core.DEFAULT_FORMAT)
    s.add_argument('-t', type=str, required=False, default="Split Secret",
                   metavar='SECRET_NAME',
                   help="name of secret to include on QRCODE images")
    s.add_argument('-k', required=False, action='store_true',
                   help="skip combine check after splitting")
    m = sp.add_parser('combine',
                      help="Combine shares and reconstruct secret.")
    m.add_argument('in_dirs', type=str, nargs='+',
                   metavar='DIR',
                   help="one or more directories containing input files to "
                   "combine (.dat data files or .png qrcode images)")
    m.add_argument('-o', type=str, required=False,
                   metavar='OUT_FILE',
                   help="write secret to output file, or stdout if omitted")

    args = parser.parse_args()
    if args.command == 'split':
        return core.run_cmd(core.do_split, args.i, args.out_dir, fmt=args.f,
                            n=args.n, m=args.m,
                            secret_name=args.t, skip_merge_check=args.k)
    elif args.command == 'combine':
        return core.run_cmd(core.do_merge, args.in_dirs, args.o)
    else:
        print(f"Invalid command: {args.command}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
