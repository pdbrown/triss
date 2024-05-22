import pytest
from hypothesis import example, given, settings, strategies as st, HealthCheck
import copy
import itertools
from pathlib import Path
import random
import tempfile

from . import gen_common
from .. import helpers

from triss.byte_seqs import resize_seqs
from triss.codec.memory import MemoryCodec
from triss.codec.data_file import FileEncoder, FileDecoder
try:
    from triss.codec.qrcode import QR_DATA_SIZE_BYTES, QREncoder, QRDecoder
    have_qrcode = True
except ModuleNotFoundError:
    have_qrcode = False
    QR_SIZE_DATA_BYTES = -1

def kb_stream(stream):
    return resize_seqs(1024, stream)

@st.composite
def m_and_n(draw, n=st.integers(min_value=2, max_value=10)):
    n = draw(n)
    m = draw(st.integers(min_value=2, max_value=n))
    return (m, n)


@given(data=st.lists(st.binary()), m_n=m_and_n())
def test_memory_codec(data, m_n):
    codec = MemoryCodec()
    (m, n) = m_n
    codec.encode(data, m, n)
    for aset in itertools.combinations(range(n), m):
        codec.use_authorized_set(aset)
        decoded = list(codec.decode())
        assert decoded == data


@given(data=st.lists(st.binary()), m_n=m_and_n())
def test_file_encoder_decoder(data, m_n):
    do_file_encoder_decoder(data, m_n)


@settings(max_examples=20, deadline=10000)
@given(byte_count=st.integers(min_value=16*1024, max_value=1024*1024),
       m_n=m_and_n(n=st.integers(min_value=2, max_value=8)))
def test_file_encoder_decoder_large(byte_count, m_n):
    all_bytes = random.randbytes(byte_count)
    data = list(resize_seqs(4096, [all_bytes]))
    do_file_encoder_decoder(data, m_n)

def do_file_encoder_decoder(data, m_n):
    with tempfile.TemporaryDirectory() as d:
        (m, n) = m_n
        encoder = FileEncoder(d)
        encoder.encode(data, m, n)

        share_dirs = Path(d).iterdir()
        share_asets = list(itertools.combinations(share_dirs, m))
        if not share_asets:
            assert not b''.join(data)
            return

        shares = random.choice(share_asets)
        decoder = FileDecoder(shares)

        assert list(kb_stream(decoder.decode())) == list(kb_stream(data))


@pytest.mark.skipif(not have_qrcode, reason="qrcode is not installed")
@given(data=st.lists(st.binary(max_size=3000)),
       m_n=m_and_n(n=st.integers(min_value=2, max_value=4)))
@settings(max_examples=10, deadline=20000)
# Want at least one example that spans multiple segments
@example(data=[random.randbytes(3000)], m_n=(2,4))
# Want an example consisting of full segment.
@example(data=[random.randbytes(QR_DATA_SIZE_BYTES)], m_n=(2,3))
def test_qr_encoder_decoder(data, m_n):
    do_qr_encoder_decoder(data, m_n)


@pytest.mark.skipif(not have_qrcode, reason="qrcode is not installed")
@given(data=st.lists(st.binary(max_size=50)),
       m_n=m_and_n(n=st.integers(min_value=3, max_value=8)))
@settings(max_examples=10, deadline=20000)
def test_qr_encoder_decoder_more_shares(data, m_n):
    do_qr_encoder_decoder(data, m_n)

def do_qr_encoder_decoder(data, m_n):
    with tempfile.TemporaryDirectory() as d:
        (m, n) = m_n
        encoder = QREncoder(d, "test secret")
        encoder.encode(data, m, n)

        share_dirs = Path(d).iterdir()
        share_asets = list(itertools.combinations(share_dirs, m))
        if not share_asets:
            assert not b''.join(data)
            return

        shares = random.choice(share_asets)
        decoder = QRDecoder(shares)

        try:
            data = list(kb_stream(data))
            output = list(kb_stream(decoder.decode()))
            assert output == data
        except Exception as e:
            # save_dir = helpers.save_test_files(d)
            # indata = save_dir / "input.dat"
            # with indata.open('wb') as f:
            #     for chunk in data:
            #         f.write(chunk)
            # outdata = save_dir / "output.dat"
            # with outdata.open('wb') as f:
            #     for chunk in output:
            #         f.write(chunk)
            raise e
