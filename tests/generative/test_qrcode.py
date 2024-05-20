import pytest
from hypothesis import example, given, settings, strategies as st, HealthCheck
import copy
import random

from . import gen_common

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
    except AssertionError as e:
        import subprocess
        subprocess.check_output(['mkdir', '-p', '/tmp/TEST_LOG'])
        g = subprocess.check_output(['mktemp', '/tmp/TEST_LOG/img.XXXXXX.png']).decode().strip()
        h = g + '.txt'
        subprocess.check_output(['cp', str(f), g])
        with open(h, 'wb') as hd:
            hd.write(xs)
        raise e
