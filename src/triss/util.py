# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import sys
import traceback

_verbose = False


def verbose(v=None):
    global _verbose
    if v is not None:
        _verbose = v
    return _verbose


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def print_exception(e, prefix="", file=None):
    # Set default at runtime vs def-time, so caller can call this with an
    # overridden sys.stderr.
    if not file:
        file = sys.stderr
    if verbose():
        traceback.print_exception(e, file=file)
        return
    if e.__context__ and e.__context__ != e.__cause__:
        print(prefix, "Tried to handle error:", sep='', file=file)
        print_exception(e.__context__, prefix=prefix, file=file)
        print(prefix, "But got another error in error handler:", sep='', file=file)
    if isinstance(e, ExceptionGroup):
        print(prefix, e.message, sep='', file=file)
        for sub_e in e.exceptions:
            print_exception(sub_e, prefix=prefix + "  ", file=file)
    else:
        if isinstance(e, KeyError):
            print(prefix, repr(e), sep='', file=file)
        elif e.args:
            print(prefix, e, sep='', file=file)
        if e.__cause__:
            print_exception(e.__cause__, prefix=prefix + "  ", file=file)


def iter_str(xs):
    return ", ".join(str(x) for x in xs)


def div_up(x, quot):
    return (x + quot - 1) // quot
