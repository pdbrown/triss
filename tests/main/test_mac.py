# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import pytest

import itertools
from pathlib import Path

from .. import helpers

from triss.byte_streams import resize_seqs
from triss.codec import Header, FragmentHeader, MacHeader, MacWarning, qrcode
from triss.codec.memory import MemoryCodec
from triss.codec.data_file import FileEncoder, FileDecoder
from triss.codec.qrcode import QREncoder, QRDecoder

def test_hmac_512(tmp_path):
    algo = "hmac-sha512"
    data = [b'asdf', b'qwer']
    m = 2
    n = 4
    encoder = FileEncoder(tmp_path)
    encoder.encode(data, m, n, mac_algorithm=algo)
    for aset in itertools.permutations(range(n), m):
        shares = [tmp_path / f"share-{i}" for i in aset]
        decoder = FileDecoder(shares)
        assert list(resize_seqs(4, decoder.decode())) == data
        first_aset_macs = next(iter(decoder.reference_macs.values()))
        first_segment_macs = next(iter(first_aset_macs.values()))
        mac = first_segment_macs[0]  # 1st fragment
        assert mac.algorithm == "hmac-sha512"
        assert len(mac.key) == 512 // 8
        assert len(mac.digest) == 512 // 8

def test_invalid_mac(tmp_path):
    data = [b'asdf']
    modified = [b'asdg']
    m = 2
    n = 2
    encoder = FileEncoder(tmp_path)
    encoder.encode(data, m, n)
    shares = list(tmp_path.iterdir())

    # Find part with the FragmentHeader
    share0  = shares[0]
    for part in share0.iterdir():
        with part.open('rb') as f:
            malleable = f.read()
            header, _ = Header.parse([malleable])
            if isinstance(header, FragmentHeader):
                part_file = part
                break

    cipher_g = malleable[-1] ^ 1  # make result decrypt to: f XOR 1 = g
    with part.open('wb') as f:
        f.write(malleable[0:-1])
        f.write(bytes([cipher_g]))

    decoder = FileDecoder(shares)
    with pytest.raises(MacWarning):
        assert list(resize_seqs(
            4, decoder.decode(ignore_mac_error=True))) == modified

    with pytest.raises(RuntimeError,
                       match=r".*ERROR: Unable to verify authenticity.*"):
        assert list(resize_seqs(4, decoder.decode())) == data


@pytest.mark.skipif(not helpers.HAVE_QRCODE, reason="QRCODE not available")
def test_multiple_mac_slices(tmp_path, monkeypatch):
    # Shrink QR codes to force splitting MAC over multiple slices with smaller
    # test case.
    monkeypatch.setattr(qrcode, "QR_SIZE_MAX_BYTES", 200)
    monkeypatch.setattr(qrcode, "QR_DATA_SIZE_BYTES",
                        qrcode.QR_SIZE_MAX_BYTES - FragmentHeader.size_bytes())
    monkeypatch.setattr(qrcode, "QR_MAC_DATA_SIZE_BYTES",
                        qrcode.QR_SIZE_MAX_BYTES - MacHeader.size_bytes())

    encoder = QREncoder(tmp_path, "test secret")
    data = [b'asdf', b'qwer']

    # mac_algo = "hmac-sha512"
    n = 3
    m = 2

    encoder.encode(data, m, n)
    # encoder.encode(data, m, n, mac_algorithm=mac_algo)

    shares = tmp_path.iterdir()
    decoder = QRDecoder(shares)
    data_out = [b'asdfqwer']
    assert list(decoder.decode()) == data_out
