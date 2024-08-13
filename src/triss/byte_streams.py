# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The byte_streams module provides functions for manipulating "byte streams":
iterables of byte sequence objects (bytes, bytearray, or list of bytes)
"""

import itertools


def take_and_drop(n, byte_stream):
    """
    Remove up to first N bytes from BYTE_STREAM.

    BYTE_STREAM is an iterable of byte sequences.
    Raise StopIteration if BYTE_STREAM is empty: if it contains no byte
    sequences, or all of them are empty.

    Return a tuple (head, byte_stream):
    - head is a byte string of the first N bytes
    - byte_stream is an iterator over the remaining byte sequences
    Note that no bytes are discarded: repeated invocations threading the
    returned byte_stream will eventually return all original bytes. If an
    invocation consumes only part of a byte seq, the remaining suffix is
    concatenated onto the front of the returned byte_stream.
    """
    n = int(n)
    if n <= 0:
        return b'', byte_stream

    byte_stream = iter(byte_stream)
    acc_size = 0
    acc = []

    while acc_size < n:
        try:
            chunk = next(byte_stream)
        except StopIteration:
            break
        acc.append(chunk)
        acc_size += len(chunk)

    if acc_size == 0:
        # Then input was empty or consisted entirely of empty byte strings,
        # signal StopIteration
        raise StopIteration

    head = b''
    for xs in acc[:-1]:
        head += xs

    if acc_size <= n:
        # Then use entire last chunk.
        head += acc[-1]
        return (head, byte_stream)

    # Split last chunk in acc, put suffix back onto byte_stream
    extra_bytes = acc_size - n
    split_at = len(acc[-1]) - extra_bytes
    head += acc[-1][:split_at]
    rest = acc[-1][split_at:]
    return (head, itertools.chain([rest], byte_stream))


def resize_seqs(chunk_size, byte_stream):
    """
    Return generator of byte sequences of size CHUNK_SIZE

    The last byte sequence may have fewer bytes. The BYTE_STREAM input is an
    iterable of byte sequences.
    """
    chunk_size = int(chunk_size)
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")

    while True:
        try:
            chunk, byte_stream = take_and_drop(chunk_size, byte_stream)
            if chunk:
                yield chunk
        except StopIteration:
            return
