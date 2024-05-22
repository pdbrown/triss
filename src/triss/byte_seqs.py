# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import itertools


def take_and_drop(n, byte_seqs):
    """
    Remove up to first N bytes from BYTE_SEQS.

    Raise StopIteration if byte_seqs is empty.

    BYTE_SEQS is an iterable of byte sequences.
    Return a tuple (head, byte_seqs):
    - head is a byte string of the first N bytes
    - byte_seqs is an iterator over the remaining byte sequences
    Note that no bytes are discarded: repeated invocations threading the
    returned byte_seqs will eventually return all original bytes. If an
    invocation consumes only part of a byte seq, the remaining suffix is
    concatenated onto the front of the returned byte_seqs.
    """
    n = int(n)
    if n <= 0:
        return b'', byte_seqs

    byte_seqs = iter(byte_seqs)
    acc_size = 0
    acc = []

    while acc_size < n:
        try:
            chunk = next(byte_seqs)
        except StopIteration:
            break
        acc.append(chunk)
        acc_size += len(chunk)

    if len(acc) == 0:
        # Then input was empty, signal StopIteration
        raise StopIteration

    head = b''
    for xs in acc[:-1]:
        head += xs

    if acc_size <= n:
        # Then use entire last chunk.
        head += acc[-1]
        return (head, byte_seqs)

    # Split last chunk in acc, put suffix back onto byte_seqs
    extra_bytes = acc_size - n
    split_at = len(acc[-1]) - extra_bytes
    head += acc[-1][:split_at]
    rest = acc[-1][split_at:]
    return (head, itertools.chain([rest], byte_seqs))


def resize_seqs(chunk_size, byte_seqs):
    """
    Return generator of byte sequences of size CHUNK_SIZE

    The last byte sequence may have fewer bytes. The BYTE_SEQS input is an
    iterable of byte sequences.
    """
    if chunk_size <= 0:
        raise Exception("chunk_size must be > 0")

    while True:
        try:
            chunk, byte_seqs = take_and_drop(chunk_size, byte_seqs)
            if chunk:
                yield chunk
        except StopIteration:
            return
