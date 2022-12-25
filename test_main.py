import os
import copy
import main
from hypothesis import example, given, settings, strategies as st

@given(xs=st.binary())
@example(xs=bytes())
@example(xs=bytes([0]))
@settings(max_examples=200)
def test_xor_bytes(xs):
    zeros = bytes([0] * len(xs))
    ones = bytes([255] * len(xs))
    assert main.xor_bytes(xs, xs) == zeros
    assert main.xor_bytes(xs, zeros) == xs
    complement = bytes([~b % 256 for b in xs])
    assert main.xor_bytes(xs, ones) == complement
    assert main.xor_bytes(xs, complement) == ones
    random = os.urandom(len(xs))
    assert main.xor_bytes(random, main.xor_bytes(xs, random)) == xs


@given(xs=st.binary(), n=st.integers(min_value=2, max_value=100))
@settings(max_examples=200)
def test_split_merge_data(xs, n):
    fragments = list(main.split_data(xs, n))
    assert len(fragments) == n
    merged = main.merge_data(fragments)
    assert merged == xs
    assert main.merge_data(main.split_data(xs, n)) == xs


@st.composite
def chunk_buf_and_size(draw, elements=st.binary()):
    xs = draw(st.lists(elements, min_size=0))
    size = 0
    for x in xs:
        size += len(x)
    return (xs, size)


@st.composite
def buf_size_flush(draw, elements=chunk_buf_and_size()):
    """
    Return (buf, size, n)
    - buf is list of byte strings
    - size is total number of bytes in buf
    - n is int where 0 <= n <= size
    """
    (buf, size) = draw(elements)
    return (buf, size, draw(st.integers(min_value=0, max_value=size)))


def flatten_chunks(xs):
    return b''.join(xs)


@given(bsf=buf_size_flush())
def test_flush_bytes(bsf):
    (buf, size, n) = bsf
    buf_orig = copy.deepcopy(buf)
    (head, buf_tail, size_tail) = main.flush_bytes(buf, size, n)
    t = 0
    for c in buf_tail:
        t += len(c)
    assert size_tail == t
    flat_new = head
    for c in buf_tail:
        flat_new += c
    assert flat_new == flatten_chunks(buf_orig)


@given(xs=st.lists(st.binary()), n=st.integers(min_value=1, max_value=50))
@settings(max_examples=200)
def test_resize_chunks(xs, n):
    resized = main.resize_chunks(xs, n)
    chunks = []
    for (last, x) in main.iter_islast(resized):
        if not last:
            assert len(x) == n
        else:
            assert len(x) <= n
            assert len(x) > 0
        chunks.append(x)
    assert flatten_chunks(chunks) == flatten_chunks(xs)


@given(bsf=buf_size_flush())
def test_skip_bytes(bsf):
    (buf, size, n) = bsf
    buf_orig = copy.deepcopy(buf)
    tail = list(main.skip_bytes(buf, n))
    assert flatten_chunks(tail) == flatten_chunks(buf_orig)[n:]




def test_needsfiles(tmp_path):
    file_path = os.path.join(tmp_path, "test.txt")
    with open(file_path, 'wb') as f:
        f.write(b'abc\n')
    with open(file_path, 'rb') as f:
        print(f.read())
    # print(tmp_path)
    # print("AAAAA", os.getcwd())
    assert 1
