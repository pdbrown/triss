import os
import re
import copy
import random
import tempfile
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


@given(chunks=st.lists(st.binary()))
def test_zlib(chunks):
    xs = main.gunzip_seq(main.gzip_seq(chunks))
    assert flatten_chunks(xs) == flatten_chunks(chunks)


@given(xs=st.binary(min_size=0, max_size=main.QR_SIZE_BYTES),
       caption=st.text(),
       subtitle=st.text())
@settings(max_examples=100)
def test_qrencode_decode(xs, caption, subtitle):
    with tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, 'img.png')
        img = main.qr_image_with_caption(xs, caption, subtitle=subtitle)
        img.save(f)
        decoded = main.decode_qr_code(f)
        try:
            assert decoded == xs
        except AssertionError as e:
            import subprocess
            subprocess.check_output(['mkdir', '-p', '/tmp/TEST_LOG'])
            g = subprocess.check_output(['mktemp', '/tmp/TEST_LOG/img.XXXXXX.png']).decode().strip()
            h = g + '.txt'
            subprocess.check_output(['cp', str(f), g])
            with open(h, 'wb') as hd:
                hd.write(xs)
            raise e


def list_shares(outdir):
    return [d for d in os.listdir(outdir)
            if re.match('share-\\d+', d)]


def select_shares(outdir, n_shares):
    shares = list_shares(outdir)
    random.shuffle(shares)
    return [os.path.join(outdir, d) for d in shares[0:n_shares]]


def assert_split_merge(indata, n_recover=None, **split_args):
    with tempfile.TemporaryDirectory() as d:
        infile = os.path.join(d, 'infile.dat')
        outdir = os.path.join(d, 'out')
        merged = os.path.join(d, 'merged.dat')
        # secret_name is displayed on QRCODE label, not tested here
        split_args['secret_name'] = None
        with open(infile, 'wb') as f:
            f.write(indata)
        main.do_split(infile,
                      outdir,
                      split_args['fmt'],
                      split_args['n'],
                      split_args['m'],
                      split_args['do_gzip'],
                      split_args['secret_name'])
        # import subprocess
        # print(subprocess.check_output(['find', str(d)]).decode())
        main.do_merge(select_shares(outdir, n_recover or split_args['m']),
                      merged)
        with open(merged, 'rb') as f:
            assert f.read() == indata


@st.composite
def m_and_n(draw, n=st.integers(min_value=2, max_value=10)):
    n = draw(n)
    m = draw(st.integers(min_value=2, max_value=n))
    return (m, n)


# Test recovery
## DATA
### N of N
#### Uncompressed
@given(xs=st.binary(), n=st.integers(min_value=2, max_value=20))
@settings(max_examples=200)
def test_split_data_n_of_n(xs, n):
    assert_split_merge(xs, fmt='DATA',
                       n=n, m=n,
                       do_gzip=False)


@given(n=st.integers(min_value=2, max_value=20),
       j=st.integers(min_value=0, max_value=9),
       k=st.integers(min_value=0, max_value=99))
@settings(max_examples=20)
def test_split_large_data_n_of_n(n, j, k):
    xs = os.urandom(1000000 + j * 100 + k)
    assert_split_merge(xs, fmt='DATA',
                       n=n, m=n,
                       do_gzip=False)


#### Gzip
@given(xs=st.binary(), n=st.integers(min_value=2, max_value=20))
@settings(max_examples=200)
def test_split_data_gzip_n_of_n(xs, n):
    assert_split_merge(xs, fmt='DATA',
                       n=n, m=n,
                       do_gzip=True)


@given(n=st.integers(min_value=2, max_value=20),
       j=st.integers(min_value=0, max_value=9),
       k=st.integers(min_value=0, max_value=100))
@settings(max_examples=20)
def test_split_large_data_gzip_n_of_n(n, j, k):
    xs = os.urandom(100000 + j * 100 + k)
    assert_split_merge(xs, fmt='DATA',
                       n=n, m=n,
                       do_gzip=True)


### M of N
#### Uncompressed
# m-of-n sharing opens at least (n choose m) files, and typical ulimits limit
# max number of file descriptors to 1024 per process. Keep n <=8 to avoid
# running out of file descriptors. (The python interpreter opens many files
# too, so we have to stay well under (n choose m) = 1024).
@given(xs=st.binary(), m_n=m_and_n(n=st.integers(min_value=2, max_value=8)))
@settings(max_examples=200)
def test_split_data_m_of_n(xs, m_n):
    (m, n) = m_n
    assert_split_merge(xs, fmt='DATA',
                       m=m, n=n,
                       do_gzip=False)


@given(m_n=m_and_n(n=st.integers(min_value=2, max_value=8)),
       j=st.integers(min_value=0, max_value=9),
       k=st.integers(min_value=0, max_value=99))
@settings(max_examples=20)
def test_split_large_data_n_of_n(m_n, j, k):
    (m, n) = m_n
    xs = os.urandom(10000 + j * 100 + k)
    assert_split_merge(xs, fmt='DATA',
                       m=m, n=n,
                       do_gzip=False)


#### Gzip
@given(xs=st.binary(), m_n=m_and_n(n=st.integers(min_value=2, max_value=8)))
@settings(max_examples=200)
def test_split_data_m_of_n(xs, m_n):
    (m, n) = m_n
    assert_split_merge(xs, fmt='DATA',
                       m=m, n=n,
                       do_gzip=True)


@given(m_n=m_and_n(n=st.integers(min_value=2, max_value=8)),
       j=st.integers(min_value=0, max_value=9),
       k=st.integers(min_value=0, max_value=99))
@settings(max_examples=20)
def test_split_large_data_n_of_n(m_n, j, k):
    (m, n) = m_n
    xs = os.urandom(10000 + j * 100 + k)
    assert_split_merge(xs, fmt='DATA',
                       m=m, n=n,
                       do_gzip=True)


# ## QRCODE
# ### N of N
# #### Uncompressed
# @given(xs=st.binary(), n=st.integers(min_value=2, max_value=10))
# @settings(max_examples=5)
# def test_split_qrcode_n_of_n(xs, n):
#     assert_split_merge(xs, fmt='QRCODE',
#                        n=n, m=n,
#                        do_gzip=False)


# #### Gzip
# @given(xs=st.binary(), n=st.integers(min_value=2, max_value=10))
# @settings(max_examples=5)
# def test_split_qrcode_gzip_n_of_n(xs, n):
#     assert_split_merge(xs, fmt='QRCODE',
#                        n=n, m=n,
#                        do_gzip=True)


# ### M of N
# #### Uncompressed
# @given(xs=st.binary(), m_n=m_and_n(n=st.integers(min_value=2, max_value=6)))
# @settings(max_examples=5)
# def test_split_qrcode_m_of_n(xs, m_n):
#     (m, n) = m_n
#     assert_split_merge(xs, fmt='QRCODE',
#                        m=m, n=n,
#                        do_gzip=False)


# #### Gzip
# @given(xs=st.binary(), m_n=m_and_n(n=st.integers(min_value=2, max_value=6)))
# @settings(max_examples=5)
# def test_split_qrcode_m_of_n(xs, m_n):
#     (m, n) = m_n
#     assert_split_merge(xs, fmt='QRCODE',
#                        m=m, n=n,
#                        do_gzip=True)
