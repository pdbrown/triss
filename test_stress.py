import multiprocessing
import random
import threading

import test_main

n_threads = int(max(multiprocessing.cpu_count() / 2, 1))

def tprint(thread_num, *objects, **kwargs):
    if thread_num is not None:
        print(f"[thread {thread_num}]", *objects, **kwargs)
    else:
        print(*objects, **kwargs)


def do_qrdecode(thread_num):
    n = 2
    attempts = 50
    for l in [50, 100, 200]:
        for attempt in range(attempts):
            tprint(thread_num, f"Length {l}, attempt {attempt+1}/{attempts}")
            xs = random.randbytes(l)
            test_main.assert_split_merge(xs,
                                         save_on_error=True,
                                         fmt='QRCODE', n=n, m=n,
                                         merge_quiet=True)

def test_qrdecode():
    threads = []
    for i in range(n_threads):
        t = threading.Thread(target=do_qrdecode, args=[i])
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
