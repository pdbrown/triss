# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import itertools
from pathlib import Path
import random
import tempfile

import pytest
from hypothesis import example, given, settings, strategies as st

from triss.byte_streams import resize_seqs
from triss.codec import memory, data_file, qrcode
from triss.codec.qrcode import QR_DATA_SIZE_BYTES
from .. import helpers
from . import gen_common  # noqa: F401
from .gen_common import m_and_n


@given(data=st.lists(st.binary(min_size=1), min_size=1), m_n=m_and_n())
def test_memory_codec(data, m_n):
    encoder, decoder = memory.codec()
    (m, n) = m_n
    encoder.encode(data, m, n)
    aset = random.choice(list(itertools.combinations(range(n), m)))
    decoder.reader.select_authorized_set(aset)
    decoded = list(decoder.decode())
    assert decoded == data


@given(data=st.lists(st.binary(min_size=1), min_size=1), m_n=m_and_n())
def test_file_encoder_decoder(data, m_n):
    do_file_encoder_decoder(data, m_n)


@settings(max_examples=20, deadline=30000)
@given(byte_count=st.integers(min_value=16*1024, max_value=1024*1024),
       m_n=m_and_n(n=st.integers(min_value=2, max_value=8)))
def test_file_encoder_decoder_large(byte_count, m_n):
    all_bytes = random.randbytes(byte_count)
    data = list(resize_seqs(4096, [all_bytes]))
    do_file_encoder_decoder(data, m_n)


def do_file_encoder_decoder(data, m_n):
    with tempfile.TemporaryDirectory() as d:
        (m, n) = m_n
        encoder = data_file.encoder(d)
        encoder.encode(data, m, n)

        share_dirs = Path(d).iterdir()
        share_asets = list(itertools.permutations(share_dirs, m))

        shares = random.choice(share_asets)
        decoder = data_file.decoder(shares)

        decoded = list(helpers.kb_stream(decoder.decode()))
        original = list(helpers.kb_stream(data))
        assert decoded == original


@pytest.mark.skipif(not helpers.HAVE_QRCODE, reason="QRCODE not available")
@given(data=st.lists(st.binary(min_size=1, max_size=3000), min_size=1),
       m_n=m_and_n(n=st.integers(min_value=2, max_value=4)))
@settings(max_examples=10, deadline=60000)
# Want at least one example that spans multiple segments
@example(data=[random.randbytes(3000)], m_n=(2, 4))
# Want an example consisting of full segment.
@example(data=[random.randbytes(QR_DATA_SIZE_BYTES)], m_n=(2, 3))
def test_qr_encoder_decoder(data, m_n):
    do_qr_encoder_decoder(data, m_n)


@pytest.mark.skipif(not helpers.HAVE_QRCODE, reason="QRCODE not available")
@given(data=st.lists(st.binary(min_size=1, max_size=50), min_size=1),
       m_n=m_and_n(n=st.integers(min_value=3, max_value=8)))
@settings(max_examples=10, deadline=60000)
def test_qr_encoder_decoder_more_shares(data, m_n):
    do_qr_encoder_decoder(data, m_n)


def do_qr_encoder_decoder(data, m_n):
    with tempfile.TemporaryDirectory() as d:
        (m, n) = m_n
        encoder = qrcode.encoder(d, "test secret")
        encoder.encode(data, m, n)

        share_dirs = Path(d).iterdir()
        share_asets = list(itertools.permutations(share_dirs, m))
        if not share_asets:
            assert not b''.join(data)
            return

        shares = random.choice(share_asets)
        decoder = qrcode.decoder(shares)

        try:
            decoded = list(helpers.kb_stream(decoder.decode()))
            original = list(helpers.kb_stream(data))
            assert decoded == original
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
