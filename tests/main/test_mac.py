# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import pytest

import itertools

from .. import helpers

from triss.byte_streams import resize_seqs
from triss.codec import MacWarning, data_file, qrcode
from triss.header import Header, FragmentHeader

def test_hmac_512(tmp_path):
    algo = "hmac-sha512"
    data = [b'asdf', b'qwer']
    m = 2
    n = 4
    encoder = data_file.encoder(tmp_path, mac_algorithm=algo)
    encoder.encode(data, m, n)
    for aset in itertools.permutations(range(n), m):
        shares = [tmp_path / f"share-{i}" for i in aset]
        decoder = data_file.decoder(shares)
        assert list(resize_seqs(4, decoder.decode())) == data
        first_aset_macs = next(iter(decoder.reference_macs.values()))
        first_fragment_macs = next(iter(first_aset_macs.values()))
        mac = next(iter(first_fragment_macs.values()))
        assert mac.algorithm == "hmac-sha512"
        assert len(mac.key) == 512 // 8
        assert len(mac.digest) == 512 // 8

def test_invalid_mac(tmp_path):
    data = [b'asdf']
    modified = [b'asdg']
    m = 2
    n = 2
    encoder = data_file.encoder(tmp_path)
    encoder.encode(data, m, n)
    shares = list(tmp_path.iterdir())

    # Find part with the FragmentHeader
    share0  = shares[0]
    for part in share0.iterdir():
        with part.open('rb') as f:
            malleable = f.read()
            header, _ = Header.parse([malleable])
            if isinstance(header, FragmentHeader):
                break

    cipher_g = malleable[-1] ^ 1  # make result decrypt to: f XOR 1 = g
    with part.open('wb') as f:
        f.write(malleable[0:-1])
        f.write(bytes([cipher_g]))

    decoder = data_file.decoder(shares)
    with pytest.raises(MacWarning):
        assert list(resize_seqs(
            4, decoder.decode(ignore_mac_error=True))) == modified

    with pytest.raises(RuntimeError,
                       match=r".*ERROR: Unable to verify authenticity.*"):
        assert list(resize_seqs(4, decoder.decode())) == data


def test_multiple_mac_slices_data_file(tmp_path):
    encoder = data_file.encoder(tmp_path,
                                mac_slice_size_bytes=10)
    data = [b'asdf', b'qwer']
    n = 2
    m = 2

    encoder.encode(data, m, n)

    shares = tmp_path.iterdir()
    decoder = data_file.decoder(shares)
    data_out = [b'asdfqwer']
    assert list(decoder.decode()) == data_out


@pytest.mark.skipif(not helpers.HAVE_QRCODE, reason="QRCODE not available")
def test_multiple_mac_slices_qrcode(tmp_path, monkeypatch):
    # Use larger mac digest so test works with fewer fragments
    algo = "hmac-sha512"
    encoder = qrcode.encoder(tmp_path, "test secret", mac_algorithm=algo)
    data = [b'asdf', b'qwer']
    # 64 byte (512 bit) key and digest size: 1 key, 18 digests per mac output
    # is 1216 bytes. Header is another 64 bytes for a total of:
    # 1280 bytes > the 1273 byte capacity of triss QR codes.
    n = 18
    m = 18

    encoder.encode(data, m, n)

    shares = tmp_path.iterdir()
    decoder = qrcode.decoder(shares)
    data_out = [b'asdfqwer']
    assert list(decoder.decode()) == data_out
