# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import multiprocessing
import random
import threading

from tests.main.test_core import do_split_combine, select_m_shares

n_threads = int(max(multiprocessing.cpu_count() / 2, 1))

success = True

def tprint(tid, *objects, **kwargs):
    if tid is not None:
        print(f"[thread {tid}]", *objects, **kwargs)
    else:
        print(*objects, **kwargs)


def stress_qr_codec(tid, tmp_path):
    try:
        my_path = tmp_path / f"thread-{tid}"
        my_path.mkdir()
        n = 2
        attempts = 50
        for l in [50, 100, 200]:
            for attempt in range(attempts):
                tprint(tid, f"Length {l}, attempt {attempt+1}/{attempts}")
                data = random.randbytes(l)
                do_split_combine(
                    data,
                    my_path,
                    select_m_shares(n),
                    fmt='QRCODE',
                    skip_combine_check=True)
    except Exception as e:
        global success
        success = False
        raise e

def test_stress_qr_codec(tmp_path):
    threads = []
    for i in range(n_threads):
        t = threading.Thread(target=stress_qr_codec, args=[i, tmp_path])
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    assert success
