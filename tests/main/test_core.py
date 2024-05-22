import pytest

import random

from triss import core
try:
    import triss.codec.qrcode
    have_qrcode = True
except ModuleNotFoundError:
    have_qrcode = False

def select_m_shares(m):
    def choose_m_shares(share_dir):
        shares = list(share_dir.iterdir())
        random.shuffle(shares)
        return shares[0:m]
    return choose_m_shares


def do_split_combine(data, tmp_path, select_shares, fmt='DATA', **args):
    in_file = tmp_path / "input.dat"
    check_file = tmp_path / "check.dat"
    share_dir = tmp_path / "shares"
    with in_file.open('wb') as f:
        f.write(data)
    core.do_split(in_file, share_dir, output_format=fmt, **args)
    combine_shares = select_shares(share_dir)
    core.do_combine(combine_shares, check_file, input_format=fmt)



def test_data(tmp_path):
    data = random.randbytes(16000)
    do_split_combine(data, tmp_path, select_m_shares(2), fmt='DATA', m=2, n=3)

@pytest.mark.skipif(not have_qrcode, reason="qrcode is not installed")
def test_qrcode(tmp_path):
    data = random.randbytes(100)
    do_split_combine(data, tmp_path, select_m_shares(2), fmt='QRCODE', m=2, n=3)


def test_missing_share(tmp_path):
    data = random.randbytes(2000)
    do_split_combine(data, tmp_path, select_m_shares(1), fmt='DATA', m=2, n=3)
