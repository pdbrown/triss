# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from collections import defaultdict, namedtuple
import contextlib
import itertools
import io
from pathlib import Path
import os
import re
import sys
import tempfile

from triss.byte_streams import resize_seqs
from triss.codec import data_file
from triss.util import ErrorMessage, eprint, iter_str

try:
    from triss.codec import qrcode
    have_qrcode = True
except ModuleNotFoundError:
    have_qrcode = False

# Triss relies on dict behavior as of 3.7:
# - Dictionary order is guaranteed to be insertion order
if sys.version_info < (3, 7):
    eprint("Error: Python version is too old. Need at least 3.7 but running:")
    eprint(sys.version)
    sys.exit(1)

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

def assert_byte_streams_equal(bs_x, bs_y, err_msg="Byte seqs not equal!"):
    bs_x = resize_seqs(4096, bs_x)
    bs_y = resize_seqs(4096, bs_y)

    for (xs, ys) in zip(bs_x, bs_y):
        if xs != ys:
            raise ErrorMessage(err_msg)
    for bs in [bs_x, bs_y]:
        try:
            next(bs)
            # Ensure byte seqs have same length. Should be empty so expect
            # StopIteration.
            raise ErrorMessage(err_msg)
        except StopIteration:
            pass

def check_asets_combine(in_file, out_dir, m, input_format):
    with tempfile.TemporaryDirectory() as d:
        for share_dirs in authorized_share_sets(out_dir, m):
            f = Path(d) / "check_output"
            try:
                do_combine(share_dirs, f, input_format)
            except ErrorMessage as e:
                eprint(e)
                raise ErrorMessage(
                    "Combine check failed! Unable to combine shares in " \
                    f"{iter_str(share_dirs)}.")
            if in_file:
                assert_byte_streams_equal(
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
            raise ErrorMessage(f"QRCODE encoder is not available.")
    else:
        raise ErrorMessage(f"Unknown output format {output_format}.")

    m = m or n
    encoder.encode(read_buffered(in_file), m, n)

    if not skip_combine_check:
        check_asets_combine(in_file, out_dir, m, output_format)


def try_decode(mk_decoder, dirs, out_file):
    try:
        decoder = mk_decoder(dirs)
        eprint("Try decoding with", decoder.name())
        output_chunks = decoder.decode()
        n_chunks = 0
        with open_output(out_file) as f:
            for chunk in output_chunks:
                if chunk:
                    f.write(chunk)
                    n_chunks += 1
        if n_chunks > 0:
            return True
        else:
            eprint("Got no output.")
    except Exception as e:
        eprint("Failed to decode with", e)
    return False

def do_combine(dirs, out_file, input_format=None):
    if input_format == 'DATA':
        mk_decoders = [data_file.FileDecoder]
    elif input_format == 'QRCODE':
        if have_qrcode:
            mk_decoders = [qrcode.QRDecoder]
        else:
            raise ErrorMessage(f"QRCODE decoder is not available.")
    else:
        mk_decoders = TRY_DECODERS

    print_errors = True
    try:
        with contextlib.redirect_stderr(io.StringIO()) as captured_err:
            loop_msg = ""
            for mk_decoder in mk_decoders:
                if loop_msg:
                    eprint(loop_msg)
                if try_decode(mk_decoder, dirs, out_file):
                    print_errors = False
                    return True
                loop_msg = "Trying next decoder."
    finally:
        if print_errors:
            err = captured_err.getvalue()
            if err:
                eprint(err, end='')

    raise ErrorMessage(f"Unable to decode data in {iter_str(dirs)}.")
