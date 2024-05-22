import pytest

import itertools

from triss.crypto import fletchers_checksum_16, xor_bytes, \
    split_secret, combine_fragments


def test_fletchers_checksum_16():
    c1 = fletchers_checksum_16(b'asdf')
    c2 = fletchers_checksum_16(b'asfd')
    assert len(c1) == len(c2) == 2
    assert c1 != c2
    assert fletchers_checksum_16(b'asdf') == c1


def test_xor_bytes():
    assert xor_bytes(bytes([0x2]), bytes([0x3])) == bytes([0x1])

    xs = b'asdf'
    ys = b'qwer'
    zs = xor_bytes(xs, ys)
    assert xs != ys
    assert xs != zs
    assert xor_bytes(xs, zs) == ys
    assert xor_bytes(ys, zs) == xs

def test_split_combine():
    xs = b'asdf'
    zeros = b'\x00\x00\x00\x00'
    frags = list(split_secret(xs, 3))
    assert len(frags) == 3
    for frag in frags:
        assert len(frag) == 4
    for f1, f2, f3 in [[0, 1, 2], [0, 2, 1], [1, 2, 0]]:
        if frags[f1] == zeros and frags[f2] == zeros:
            # Highly unlikely we get here, but have gotten here so bail early.
            assert frags[f3] == xs
            return

    for frag in frags:
        assert frag != xs
    for subset in [[0], [1], [2], [0,1], [0,2], [1,2]]:
        check_frags = [frags[i] for i in subset]
        assert combine_fragments(check_frags) != xs
    assert combine_fragments(frags) == xs
