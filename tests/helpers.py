# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from pathlib import Path
import subprocess

from triss import byte_streams
from triss.util import eprint
from triss.codec import qrcode

try:
    qrcode.encoder(".", "dummy")
    qrcode.decoder(["."])
    HAVE_QRCODE = True
except Exception:
    HAVE_QRCODE = False

def save_test_files(temporary_dir):
    """
    Call this to preserve test data files.

    This isn't needed for standard pytest tests with the 'tmp_path' fixture,
    since that saves failed test output by default. But if you're making custom
    tempfile.TemporaryDirectory()'ies in generative "hypothesis" tests, this
    function is a useful debugging aid.
    """
    save_dir = subprocess.check_output(['mktemp', '-d']).decode().strip()
    try:
        subprocess.check_output(['rsync', '-a', temporary_dir, save_dir],
                                stderr=subprocess.STDOUT).decode()
    except subprocess.CalledProcessError as e:
        eprint(f"Failed to save test files with: {' '.join(e.cmd)}")
        eprint(f"Exit status: {e.returncode}")
        if e.output:
            eprint(f"Output: {e.output}")
    print("Saved test files to", save_dir)
    return Path(save_dir)

def kb_stream(stream):
    return byte_streams.resize_seqs(1024, stream)
