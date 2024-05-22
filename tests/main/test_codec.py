# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import pytest

import itertools
from pathlib import Path

from triss.byte_seqs import resize_seqs
from triss.codec import Header
from triss.codec.memory import MemoryCodec
from triss.codec.data_file import FileEncoder, FileDecoder
try:
    from triss.codec.qrcode import QREncoder, QRDecoder
    have_qrcode = True
except ModuleNotFoundError:
    have_qrcode = False


def test_header():
    h = Header.create(segment_id=1, aset_id=2, fragment_id=3)
    h.set_flag(Header.FLAG_LAST_FRAGMENT)
    assert h.segment_id == 1
    assert h.aset_id == 2
    assert h.fragment_id == 3
    assert h.test_flag(Header.FLAG_LAST_FRAGMENT)

    h_bytes = h.to_bytes()

    parsed = Header.parse(h_bytes)
    assert parsed.segment_id == h.segment_id
    assert parsed.aset_id == h.aset_id
    assert parsed.fragment_id == h.fragment_id
    assert parsed.test_flag(Header.FLAG_LAST_FRAGMENT)
    assert parsed.version == h.version

def test_memory_codec():
    codec = MemoryCodec()
    data = [b'asdf', b'qwer']
    m = 2
    n = 4

    codec.encode(data, m, n)

    for aset in itertools.combinations(range(n), m):
        codec.use_authorized_set(aset)
        decoded = list(codec.decode())
        # print(f"Input:  {data}")
        # print(f"Result: {decoded}")
        assert decoded == data

def test_file_encoder_decoder(tmp_path):
    encoder = FileEncoder(tmp_path)
    shares = [tmp_path / "share-1",
              tmp_path / "share-3"]
    decoder = FileDecoder(shares)
    data = [b'asdf', b'qwer']
    m = 2
    n = 4

    encoder.encode(data, m, n)

    data_out = [b'asd', b'fqw', b'er']
    assert list(resize_seqs(3, decoder.decode())) == data_out


@pytest.mark.skipif(not have_qrcode, reason="qrcode is not installed")
def test_qr_encoder_decoder(tmp_path):
    encoder = QREncoder(tmp_path, "test secret")
    shares = [tmp_path / "share-1",
              tmp_path / "share-3"]
    decoder = QRDecoder(shares)
    data = [b'asdf', b'qwer']
    m = 2
    n = 4

    encoder.encode(data, m, n)

    data_out = [b'asdfqwer']
    assert list(decoder.decode()) == data_out
