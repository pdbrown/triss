# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import sys

class ErrorMessage(Exception):
    pass

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def iter_str(xs):
    return ", ".join(str(x) for x in xs)

def div_up(x, quot):
    return (x + quot - 1) // quot
