# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import contextlib
import itertools
import io
from pathlib import Path
import os
import re
import sys
import tempfile
import traceback

from triss.byte_streams import resize_seqs
from triss.codec import MacWarning, data_file
from triss.util import eprint, iter_str, print_exception, verbose
from triss.codec import qrcode

def python_version_check(args):
    """
    Assert python version.

    Important python features:
    Version 3.7:
    - CRITICAL! Dictionary order is guaranteed to be insertion order
    Version 3.10:
    - traceback.print_exception(exc) now accepts an Exception as the first arg
      (only used in verbose mode)
    Version 3.11:
    - ExceptionGroup used to report header parse errors.
    """
    if sys.version_info < (3, 11):
        eprint(
            "Error: Python version is too old. Need at least 3.11 but ""have:")
        eprint(sys.version)
        sys.exit(1)

DEFAULT_FORMAT='DATA'
TRY_DECODERS = [data_file.FileDecoder, qrcode.QRDecoder]


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

def assert_byte_streams_equal(bs_x, bs_y, err_msg="Byte streams not equal!"):
    bs_x = resize_seqs(4096, bs_x)
    bs_y = resize_seqs(4096, bs_y)

    for (xs, ys) in zip(bs_x, bs_y):
        if xs != ys:
            raise AssertionError(err_msg)
    for bs in [bs_x, bs_y]:
        try:
            next(bs)
            # Ensure byte seqs have same length. Should be empty so expect
            # StopIteration.
            raise AssertionError(err_msg)
        except StopIteration:
            pass

def assert_all_authorized_sets_combine(in_file, out_dir, m, input_format):
    with tempfile.TemporaryDirectory() as d:
        for share_dirs in authorized_share_sets(out_dir, m):
            f = Path(d) / "check_output"
            try:
                do_combine(share_dirs, f, input_format)
            except Exception as e:
                raise AssertionError(
                    "Combine check failed! Unable to combine shares in "
                    f"{iter_str(share_dirs)}.") from e
            if in_file:
                assert_byte_streams_equal(
                    read_buffered(in_file),
                    read_buffered(f),
                    err_msg=("Combine check failed! Result of combining "
                             "shares is not equal to original input."))
            f.unlink()

    if not in_file:
        eprint("Warning: Requested combine-check after splitting, but data "
               "was provided on stdin, so can't confirm integrity of "
               "combined result.")


def do_split(in_file, out_dir, output_format=DEFAULT_FORMAT, m=2, n=2,
             secret_name="Split secret", skip_combine_check=False):
    if output_format == 'DATA':
        encoder = data_file.FileEncoder(out_dir)
    elif output_format == 'QRCODE':
        encoder = qrcode.QREncoder(out_dir, secret_name)
    else:
        raise ValueError(f"Unknown output format {output_format}.")

    m = m or n
    try:
        encoder.encode(read_buffered(in_file), m, n)
    except Exception as e:
        raise Exception(
            f"Failed to split secret in {output_format} format.") from e
    if not skip_combine_check:
        assert_all_authorized_sets_combine(in_file, out_dir, m, output_format)


def try_decode(mk_decoder, dirs, out_file, ignore_mac_error):
    """
    Try to decode. Return False on error, or tuple of (True, print_errors)

    where print_errors is a boolean.
    """
    try:
        decoder = mk_decoder(dirs)
    except Exception as e:
        eprint(f"Failed to build decoder with factory function: {mk_decoder}")
        print_exception(e)
        return False
    try:
        eprint("Try decoding with", decoder.name)
        output_chunks = decoder.decode(ignore_mac_error)
        n_chunks = 0
        with open_output(out_file) as f:
            for chunk in output_chunks:
                if chunk:
                    f.write(chunk)
                    n_chunks += 1
        if n_chunks > 0:
            if verbose():
                eprint(f"Successfully decoded with {decoder.name}!")
            return (True, verbose())  # success, print messages in verbose mode
        else:
            eprint("Got no output.")
    except MacWarning:
        decoder.eprint(
            "WARNING: Decoded entire input, but unable to verify authenticity "
            "of output. Inputs may have been tampered with!")
        if verbose():
            traceback.print_exc()
        return (True, True)  # success, do print errors
    except Exception as e:
        decoder.print_registered_headers()
        decoder.eprint("And failed to decode with:")
        print_exception(e)
    return False

def do_combine(dirs, out_file, input_format=None, ignore_mac_error=False):
    if input_format == 'DATA':
        mk_decoders = [data_file.FileDecoder]
    elif input_format == 'QRCODE':
        mk_decoders = [qrcode.QRDecoder]
    else:
        mk_decoders = TRY_DECODERS

    print_errors = True
    if verbose():
        # Don't interfere with stderr
        cm = contextlib.nullcontext(None)
    else:
        # Suppress stderr, only print it if none of the decoders ar successful.
        cm = contextlib.redirect_stderr(io.StringIO())
    try:
        with cm as captured_err:
            loop_msg = ""
            for mk_decoder in mk_decoders:
                if loop_msg:
                    eprint(loop_msg)
                ret = try_decode(mk_decoder, dirs, out_file, ignore_mac_error)
                if ret:
                    _, print_errors = ret
                    return True
                loop_msg = "Trying next decoder."
    finally:
        if print_errors and hasattr(captured_err, 'getvalue'):
            err = captured_err.getvalue()
            if err:
                eprint(err, end='')

    raise RuntimeError(f"Unable to decode data in {iter_str(dirs)}.")
