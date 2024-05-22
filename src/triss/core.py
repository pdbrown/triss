from collections import defaultdict, namedtuple
import contextlib
import itertools
from pathlib import Path
import os
import re
import sys
import tempfile

from triss.byte_seqs import resize_seqs
from triss.codec import data_file
from triss.util import eprint, FatalError

try:
    from triss.codec import qrcode
    have_qrcode = True
except ModuleNotFoundError:
    have_qrcode = False


DEFAULT_FORMAT='DATA'
TRY_DECODERS = [data_file.FileDecoder]
if have_qrcode:
    TRY_DECODERS.append(qrcode.QRDecoder)


def open_input(path):
    if path:
        return open(path, 'rb')
    else:
        return contextlib.nullcontext(sys.stdin.buffer)

def open_output(path):
    if path:
        return open(path, 'wb')
    else:
        return contextlib.nullcontext(sys.stdout.buffer)

def read_buffered(path):
    with open_input(path) as f:
        chunk = f.read1()
        while chunk:
            yield chunk
            chunk = f.read1()

def authorized_share_sets(share_parent_dir, m):
    share_dirs = Path(share_parent_dir).iterdir()
    return itertools.combinations(share_dirs, m)

def assert_byte_seqs_equal(bs_x, bs_y, err_msg="Byte seqs not equal!"):
    bs_x = resize_seqs(4096, bs_x)
    bs_y = resize_seqs(4096, bs_y)

    for (xs, ys) in zip(bs_x, bs_y):
        if xs != ys:
            raise FatalError(err_msg)
    for bs in [bs_x, bs_y]:
        try:
            next(bs)
            # Ensure byte seqs have same length. Should be empty so expect
            # StopIteration.
            raise FatalError(err_msg)
        except StopIteration:
            pass

def check_asets_combine(in_file, out_dir, m, input_format):
    with tempfile.TemporaryDirectory() as d:
        for share_dirs in authorized_share_sets(out_dir, m):
            f = Path(d) / "check_output"
            try:
                do_combine(share_dirs, f, input_format)
            except FatalError as e:
                for arg in e.args:
                    eprint(arg)
                raise FatalError(
                    "Combine check failed! Unable to combine shares in " \
                    f"in {share_dirs}.")
            if in_file:
                assert_byte_seqs_equal(
                    read_buffered(in_file),
                    read_buffered(f),
                    err_msg="Combine check failed! Result of combining " \
                            "shares is not equal to original input.")
            f.unlink()

    if not in_file:
        eprint("Warning: Requested combine-check after splitting, but data " \
               "was provided on stdin, so can't confirm integrity of " \
               "combined result.")



def do_split(in_file, out_dir,
             output_format=DEFAULT_FORMAT, m=2, n=2,
             secret_name="Split secret", skip_combine_check=False):

    if output_format == 'DATA':
        encoder = data_file.FileEncoder(out_dir)
    elif output_format == 'QRCODE':
        if have_qrcode:
            encoder = qrcode.QREncoder(out_dir, secret_name)
        else:
            raise FatalError(f"QRCODE encoder is not available.")
    else:
        raise FatalError(f"Unknown output format {output_format}.")

    encoder.encode(read_buffered(in_file), m, n)

    if not skip_combine_check:
        check_asets_combine(in_file, out_dir, m, output_format)


def do_combine(dirs, out_file, input_format=None):
    if input_format == 'DATA':
        mk_decoders = [data_file.FileDecoder]
    elif input_format == 'QRCODE':
        if have_qrcode:
            mk_decoders = [qrcode.QRDecoder]
        else:
            raise FatalError(f"QRCODE decoder is not available.")
    else:
        mk_decoders = TRY_DECODERS

    for mk_decoder in TRY_DECODERS:
        decoder = mk_decoder(dirs)
        output_chunks = decoder.decode()
        n_chunks = 0
        with open_output(out_file) as f:
            for chunk in output_chunks:
                if chunk:
                    f.write(chunk)
                    n_chunks += 1
        if n_chunks > 0:
            return True
    raise FatalError(f"Unable to decode data in {dirs}.")
