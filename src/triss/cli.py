# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import argparse
import sys

from triss import core, util
from triss.util import print_exception


def cli():
    parser = argparse.ArgumentParser(
        prog="triss",
        description="""Trivial secret sharing.
    Split input into M-of-N shares or recover input from a set of shares.""")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="verbose mode: log messages and tracebacks to "
                        "stderr")

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
    s.add_argument('-c', required=False, choices=['DATA', 'QRCODE'],
                   default=core.DEFAULT_FORMAT,
                   help="output file format, defaults to " +
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
                   "combine")
    m.add_argument('-c', required=False, choices=['DATA', 'QRCODE'],
                   help="input file format, will guess if omitted")
    m.add_argument('-o', type=str, required=False,
                   metavar='OUT_FILE',
                   help="write secret to output file, or stdout if omitted")
    m.add_argument('--DANGER-allow-invalid', required=False,
                   action='store_true',
                   help="Don't stop decoding on message authentication error. "
                   "WARNING! There is no guarantee the decoded output matches "
                   "the original input.")

    m = sp.add_parser('identify',
                      help="Describe a share and check its integrity.")
    m.add_argument('in_dirs', type=str, nargs='+',
                   metavar='DIR',
                   help="one or more directories containing input files to "
                   "identify")
    m.add_argument('-c', required=False, choices=['DATA', 'QRCODE'],
                   help="input file format, will guess if omitted")

    args = parser.parse_args()
    core.python_version_check()
    fmt = args.c or 'ALL'
    if args.verbose:
        util.verbose(True)
    if args.command == 'split':
        core.do_split(args.i, args.out_dir, output_format=fmt,
                      m=args.m, n=args.n,
                      secret_name=args.t, skip_combine_check=args.k)
    elif args.command == 'combine':
        core.do_combine(args.in_dirs, args.o, fmt,
                        ignore_mac_error=args.DANGER_allow_invalid)
    elif args.command == 'identify':
        core.do_identify(args.in_dirs, fmt)
    else:
        raise ValueError(f"Invalid command: {args.command}")


def main():
    try:
        cli()
        return 0
    except Exception as e:
        print_exception(e)
        return 1


if __name__ == '__main__':
    sys.exit(main())
