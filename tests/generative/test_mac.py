# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import pytest
from hypothesis import example, given, settings, strategies as st, HealthCheck
import itertools
from pathlib import Path
import random
import shutil
import tempfile

from . import gen_common
from .gen_common import m_and_n
from .. import helpers

from triss.byte_streams import resize_seqs
from triss.codec import Header, IntField, StrField
from triss.codec.memory import MemoryCodec
from triss.codec.data_file import FileEncoder, FileDecoder
from triss.codec.qrcode import QR_DATA_SIZE_BYTES, QREncoder, QRDecoder

def flip_bit(shares):
    share = random.choice(shares)
    part = random.choice(list(share.iterdir()))
    with part.open('rb+') as f:
        data = f.read()
        i = random.randint(0, len(data) - 1)
        b = data[i]
        j = random.randint(0, 7)  # which bit to flip
        b = b ^ (1 << j)  # xor to flip it
        f.seek(i)
        f.write(bytes([b]))

def delete_bytes(shares):
    share = random.choice(shares)
    part = random.choice(list(share.iterdir()))
    with part.open('rb+') as f:
        data = f.read()
        i = random.randint(0, len(data) - 2)
        j = random.randint(i, len(data) - 1)
        new_data = data[0:i] + data[j:]
        f.seek(0)
        f.truncate()
        f.write(new_data)

def corrupt_header(shares):
    share = random.choice(shares)
    part = random.choice(list(share.iterdir()))
    with part.open('rb+') as f:
        data = f.read()
        (header, bs) = Header.parse([data])
        fields = [v
                  for v
                  in header.__fields__.values()
                  if isinstance(v, IntField) or isinstance(v, StrField)]
        field = random.choice(fields)
        v = getattr(header, field.name)
        if isinstance(field, IntField):
            v += random.randint(1, (2**(field.size*8) - 1))
        elif isinstance(field, StrField):
            chars = list(v)
            random.shuffle(chars)
            v = "".join(chars) + "X"
        setattr(header, field.name, v)
        f.seek(0)
        f.write(header.to_bytes())

@given(data=st.lists(st.binary(min_size=1), min_size=1),
       n=st.integers(min_value=2, max_value=10))
def test_corruption_detected(data, n):
    m = n
    with (tempfile.TemporaryDirectory() as d,
          tempfile.TemporaryDirectory() as save_dir):
        save_dir = Path(save_dir)
        encoder = FileEncoder(d)
        encoder.encode(data, m, n)
        share_dirs = Path(d).iterdir()
        share_asets = list(itertools.permutations(share_dirs, m))
        shares = random.choice(share_asets)
        for share in shares:
            shutil.copytree(share, save_dir / "orig", dirs_exist_ok=True)
        corruptor = random.choice([
            flip_bit,
            delete_bytes,
            corrupt_header])
        corruptor(shares)
        decoder = FileDecoder(shares)
        with pytest.raises(Exception):
            for chunk in decoder.decode():
                pass
            # Save output if it didn't trigger an error
            for share in shares:
                shutil.copytree(share, save_dir / "corrupt",
                                dirs_exist_ok=True)
            helpers.save_test_files(save_dir)
