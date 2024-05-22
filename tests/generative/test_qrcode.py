# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import pytest
from hypothesis import example, given, settings, strategies as st, HealthCheck
import copy
import random

from . import gen_common
from .. import helpers

from triss import byte_seqs
from triss import crypto
try:
    from triss.codec import qrcode
    from triss.codec.qrcode import QR_SIZE_MAX_BYTES
    have_qrcode = True
except ModuleNotFoundError:
    have_qrcode = False
    QR_SIZE_MAX_BYTES = -1

@pytest.mark.skipif(not have_qrcode, reason="qrcode is not installed")
@given(xs=st.binary(min_size=0, max_size=QR_SIZE_MAX_BYTES),
       caption=st.text(),
       subtitle=st.text())
@settings(max_examples=500, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_qrencode_decode(xs, caption, subtitle, tmp_path):
    f = tmp_path / "img.png"
    img = qrcode.qr_image_with_caption(xs, caption, subtitle=subtitle)
    img.save(f)
    decoded = qrcode.decode_qr_code(f)
    try:
        assert decoded == xs
    except Exception as e:
        indata = tmp_path / "input.dat"
        with indata.open('wb') as f:
            f.write(xs)
        outdata = tmp_path / "output.dat"
        with outdata.open('wb') as f:
            f.write(decoded)
        raise e
