# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import shutil
import random

import pytest

from triss import core
from .. import helpers

def select_m_shares(m):
    def fn(share_dir):
        shares = list(share_dir.iterdir())
        random.shuffle(shares)
        return shares[0:m]
    return fn

def select_m_shares_and_duplicate_fragment(m):
    def fn(share_dir):
        shares = select_m_shares(m)(share_dir)
        fragments = list(shares[0].iterdir())
        shutil.copy(fragments[0], shares[0] / "frag_copy.dat")
        return shares
    return fn

def select_m_shares_and_corrupt_fragment(m):
    def fn(share_dir):
        shares = select_m_shares(m)(share_dir)
        empty_frag = shares[0] / "empty.dat"
        broken1_frag = shares[0] / "broken1.dat"
        broken2_frag = shares[0] / "broken2.dat"
        empty_frag.open('wb').close()
        with broken1_frag.open('wb') as f:
            f.write(random.randbytes(5))
        with broken2_frag.open('wb') as f:
            f.write(random.randbytes(500))
        return shares
    return fn


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

@pytest.mark.skipif(not helpers.HAVE_QRCODE, reason="QRCODE not available")
def test_qrcode(tmp_path):
    data = random.randbytes(100)
    do_split_combine(data, tmp_path, select_m_shares(2), fmt='QRCODE',
                     m=2, n=3)


def test_missing_share(tmp_path):
    data = random.randbytes(2000)
    with pytest.raises(RuntimeError):
        do_split_combine(data, tmp_path, select_m_shares(1), m=2, n=3)

def test_duplicate_fragment(tmp_path):
    data = random.randbytes(2000)
    do_split_combine(data, tmp_path, select_m_shares_and_duplicate_fragment(2),
                     m=2, n=3)

def test_ignore_corrupted_fragment(tmp_path):
    data = random.randbytes(2000)
    do_split_combine(data, tmp_path, select_m_shares_and_corrupt_fragment(2),
                     m=2, n=3)
