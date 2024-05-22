# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from pathlib import Path
import subprocess


def save_test_files(temporary_dir):
    """
    Call this to preserve test data files.

    This isn't needed for standard pytest tests with the 'tmp_path' fixture,
    since that saves failed test output by default. But if you're making custom
    tempfile.TemporaryDirectory()'ies in generative "hypothesis" tests, this
    function is a useful debugging aid.
    """
    save_dir = subprocess.check_output(['mktemp', '-d']).decode().strip()
    print(subprocess.check_output(
        ['rsync', '-av', temporary_dir, save_dir]).decode())
    print("Saved test files to", save_dir)
    return Path(save_dir)
