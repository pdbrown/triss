# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import pytest

import itertools
from pathlib import Path

from triss.byte_seqs import resize_seqs
from triss.codec import Header, FragmentHeader
from triss.codec.memory import MemoryCodec
from triss.codec.data_file import FileEncoder, FileDecoder
try:
    from triss.codec.qrcode import QREncoder, QRDecoder, QR_MAC_DATA_SIZE_BYTES
    have_qrcode = True
except ModuleNotFoundError:
    have_qrcode = False
    QR_MAC_DATA_SIZE_BYTES = 0


def test_fragment_header():
    h = FragmentHeader(aset_id=1,
                       segment_id=2, segment_count=3,
                       fragment_id=4, fragment_count=5)
    assert h.aset_id == 1
    assert h.segment_id == 2
    assert h.segment_count == 3
    assert h.fragment_id == 4
    assert h.fragment_count == 5
    assert h.version == FragmentHeader.VERSION
    assert h.tag == b'trissfrag'

    h_bytes = h.to_bytes()

    (parsed, byte_stream) = Header.parse([h_bytes])
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

# @pytest.mark.skipif(not have_qrcode, reason="qrcode is not installed")
# def test_qr_encoder_decoder_large_mac(tmp_path):
#     encoder = QREncoder(tmp_path, "test secret")
#     data = [b'asdf', b'qwer']

#     # Make enough splits to force hmac data onto at least 2 qrcodes.
#     mac_size_bits = 512
#     mac_size_bytes = 512 // 8
#     n = (QR_MAC_DATA_SIZE_BYTES // mac_size_bytes) + 1
#     m = n
#     encoder.encode(data, m, n, mac_size_bits=mac_size_bits)

#     shares = tmp_path.iterdir()
#     decoder = QRDecoder(shares)
#     data_out = [b'asdfqwer']
#     assert list(decoder.decode()) == data_out
