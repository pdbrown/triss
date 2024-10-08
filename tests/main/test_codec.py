# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import itertools

import pytest

from triss import paper
from triss.byte_streams import resize_seqs
from triss.codec import memory, data_file, qrcode
from triss.header import Header, FragmentHeader
from .. import helpers
from . import test_core


def test_fragment_header():
    h = FragmentHeader(aset_id=1,
                       segment_id=2, segment_count=3,
                       fragment_id=4, fragment_count=5)
    assert h.aset_id == 1
    assert h.segment_id == 2
    assert h.segment_count == 3
    assert h.fragment_id == 4
    assert h.fragment_count == 5
    assert h.version == FragmentHeader.__fields__['version'].default
    assert h.tag == b'trissfrag'

    h_bytes = h.to_bytes()

    parsed, byte_stream = Header.parse([h_bytes])
    with pytest.raises(StopIteration):
        next(byte_stream)
    assert parsed.aset_id == h.aset_id
    assert parsed.segment_id == h.segment_id
    assert parsed.segment_count == h.segment_count
    assert parsed.segment_id == h.segment_id
    assert parsed.fragment_count == h.fragment_count
    assert parsed.version == h.version
    assert parsed.tag == h.tag


def test_memory_codec():
    encoder, decoder = memory.codec()
    data = [b'asdf', b'qwer']
    m = 2
    n = 4

    encoder.encode(data, m, n)

    for aset in itertools.permutations(range(n), m):
        decoder.reader.select_authorized_set(aset)
        decoded = list(decoder.decode())
        # print(f"Input:  {data}")
        # print(f"Result: {decoded}")
        assert decoded == data


def test_file_encoder_decoder(tmp_path):
    data = [b'asdf', b'qwer']
    data_out = [b'asd', b'fqw', b'er']
    m = 2
    n = 4
    encoder = data_file.encoder(tmp_path)
    encoder.encode(data, m, n)
    for aset in itertools.permutations(range(n), m):
        shares = [tmp_path / f"share-{i}" for i in aset]
        decoder = data_file.decoder(shares)
        assert list(resize_seqs(3, decoder.decode())) == data_out


@pytest.mark.skipif(not helpers.HAVE_QRCODE, reason="QRCODE not available")
def test_qr_encoder_decoder(tmp_path):
    data = [b'asdf', b'qwer']
    data_out = [b'asdfqwer']
    m = 2
    n = 4
    encoder = qrcode.encoder(tmp_path, "test secret")
    encoder.encode(data, m, n)
    for aset in itertools.permutations(range(n), m):
        shares = [tmp_path / f"share-{i}" for i in aset]
        decoder = qrcode.decoder(shares)
        assert list(decoder.decode()) == data_out


@pytest.mark.skipif(not helpers.HAVE_QRCODE, reason="QRCODE not available")
def test_qr_encoder_decoder_n_up(tmp_path):
    data = [b'asdf', b'qwer']
    data_out = [b'asdfqwer']

    # 8 files per share 2 * (4 choose 1), divided into 3 pages: 3, 3, 2 images
    # per pg.
    m = 2
    n = 5
    n_up = 3

    encoder = qrcode.encoder(tmp_path, "test secret")
    encoder.encode(data, m, n)

    shares = test_core.select_m_shares(m)(tmp_path)

    for share in shares:
        inputs = list(share.iterdir())
        paper.n_up(n_up, inputs, share / "n_up.png")
        for f in inputs:
            f.unlink()

    decoder = qrcode.decoder(shares)
    assert list(decoder.decode()) == data_out
