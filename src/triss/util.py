import sys

class ErrorMessage(Exception):
    pass

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def iter_str(xs):
    return ", ".join(str(x) for x in xs)
