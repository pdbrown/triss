# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from hypothesis import example, given, settings, strategies as st
import copy
import random

from . import gen_common # noqa: F401

from triss import byte_streams
from triss import crypto

@st.composite
def byte_strings_and_head_length(draw):
    """
    Generate list of bytes objects and a prefix length.

    The prefix length ranges between 0 and the total length of all bytes
    objects.
    """
    byte_strings = draw(st.lists(st.binary(), min_size=0))
    size = 0
    for bs in byte_strings:
        size += len(bs)
    n = draw(st.integers(min_value=0, max_value=size))
    return (n, byte_strings)

def flatten_chunks(xs):
    return b''.join(xs)


@given(xs=st.binary())
@example(xs=bytes())
@example(xs=bytes([0]))
@settings(max_examples=200)
def test_xor_bytes(xs):
    zeros = bytes([0x00] * len(xs))
    ones = bytes([0xff] * len(xs))
    assert crypto.xor_bytes(xs, xs) == zeros
    assert crypto.xor_bytes(xs, zeros) == xs
    complement = bytes([~b % 256 for b in xs])
    assert crypto.xor_bytes(xs, ones) == complement
    assert crypto.xor_bytes(xs, complement) == ones
    pad = random.randbytes(len(xs))
    assert crypto.xor_bytes(pad, crypto.xor_bytes(xs, pad)) == xs


@given(xs=st.binary(), n=st.integers(min_value=2, max_value=100))
@settings(max_examples=200)
def test_split_combine(xs, n):
    fragments = list(crypto.split_secret(xs, n))
    assert len(fragments) == n
    if len(xs) > 0:
        if fragments[-1] != b'\x00' * len(fragments[-1]):
            broken = crypto.combine_fragments(fragments[0:-1])
            if broken == xs:
                print("LAST FRAG", fragments[-1])
                print("COMBINE FRAGS", fragments[0:-1])
            assert broken != xs
        # Else if the last fragment happens to be all zero, so won't affect the
        # XOR result, and broken == xs.
    assert crypto.combine_fragments(crypto.split_secret(xs, n)) == xs


@given(bs_head=byte_strings_and_head_length())
@settings(max_examples=200)
def test_take_and_drop(bs_head):
    n, bs = bs_head
    bs_input = copy.deepcopy(bs)
    head, bs = byte_streams.take_and_drop(n, bs)
    rest = flatten_chunks(bs)
    assert head + rest == flatten_chunks(bs_input)


@given(xs=st.lists(st.binary()), n=st.integers(min_value=1, max_value=50))
@settings(max_examples=200)
def test_resize_seqs(xs, n):
    resized = byte_streams.resize_seqs(n, xs)
    chunks = list(resized)
    for chunk in chunks[0:-1]:
        assert len(chunk) == n
    if b''.join(xs):
        assert len(chunks[-1]) <= n
    assert flatten_chunks(chunks) == flatten_chunks(xs)
