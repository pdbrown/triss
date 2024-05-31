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

class ErrorMessage(Exception):
    pass

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def print_exception(e, prefix=""):
    if verbose():
        traceback.print_exception(e)
    elif isinstance(e, ExceptionGroup):
        eprint(prefix, e.message, sep='')
        for sub_e in e.exceptions:
            print_exception(sub_e, prefix + "  ")
    else:
        if e.args:
            eprint(prefix, e, sep='')
        if e.__cause__:
            print_exception(e.__cause__, prefix + "  ")

def iter_str(xs):
    return ", ".join(str(x) for x in xs)

def div_up(x, quot):
    return (x + quot - 1) // quot
