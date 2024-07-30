# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import contextlib
import itertools
import io
from pathlib import Path
import os
import sys
import tempfile
import traceback

from triss.byte_streams import resize_seqs
from triss.codec import MacWarning, Reporter, data_file, qrcode
from triss.util import eprint, iter_str, print_exception, verbose


def python_version_check():
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
            "Error: Python version is too old. Need at least 3.11 but have:")
        eprint(sys.version)
        sys.exit(1)


DEFAULT_FORMAT = 'DATA'
DECODERS = {
    'DATA': [data_file.decoder],
    'QRCODE': [qrcode.decoder],
    'ALL': [data_file.decoder, qrcode.decoder]
}


def open_input(path):
    if path:
        try:
            return open(path, 'rb')
        except Exception as e:
            raise RuntimeError(
                f"Failed to open input file: {path}") from e
    else:
        return contextlib.nullcontext(sys.stdin.buffer)


def open_output(path):
    if path:
        try:
            return open(path, 'wb')
        except Exception as e:
            raise RuntimeError(
                f"Failed to open output file: {path}") from e
    else:
        return contextlib.nullcontext(sys.stdout.buffer)


BUFFER_SIZE = 4096 * 16


def read_buffered(path):
    with open_input(path) as f:
        chunk = f.read1(BUFFER_SIZE)
        while chunk:
            yield chunk
            chunk = f.read1(BUFFER_SIZE)


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
    eprint("Ensuring input can be recovered by combining split shares.")
    with tempfile.TemporaryDirectory() as d:
        for share_dirs in authorized_share_sets(out_dir, m):
            f = Path(d) / "check_output"
            try:
                do_combine(share_dirs, f, input_format)
            except Exception as e:
                raise AssertionError(
                    "Failed! Unable to combine shares in "
                    f"{iter_str(share_dirs)}.") from e
            # If input was from a file, check that it's identical to the
            # combined output. This is a redundant sanity check, since
            # do_combine already verifies integrity by checking HMACs.
            if in_file:
                assert_byte_streams_equal(
                    read_buffered(in_file),
                    read_buffered(f),
                    err_msg=("Failed! Result of combining shares is not "
                             "equal to original input."))
            f.unlink()


def do_split(in_file, out_dir, *, output_format=DEFAULT_FORMAT, m, n,
             secret_name="Split secret", skip_combine_check=False):
    if output_format == 'DATA':
        encoder = data_file.encoder(out_dir)
    elif output_format == 'QRCODE':
        encoder = qrcode.encoder(out_dir, secret_name)
    else:
        raise ValueError(f"Unknown output format {output_format}.")

    m = m or n

    if verbose():
        # Don't interfere with stderr
        cm = contextlib.nullcontext(None)
    else:
        # Suppress stderr, only print it if there was an error.
        cm = contextlib.redirect_stderr(io.StringIO())

    try:
        with cm as captured_err:
            encoder.encode(read_buffered(in_file), m, n)
            if hasattr(os, 'sync'):
                os.sync()
            if not skip_combine_check:
                assert_all_authorized_sets_combine(
                    in_file, out_dir, m, output_format)
            eprint("Split input successfully!")
    except Exception as e:
        if hasattr(captured_err, 'getvalue'):
            err = captured_err.getvalue()
            if err:
                eprint(err, end='')
        raise Exception(
            f"Failed to split secret in {output_format} format.") from e


def try_decode(decoder_cls, dirs, out_file, ignore_mac_error):
    """
    Try to decode. Return False on error, or tuple of (True, print_errors)

    where print_errors is a boolean.
    """
    try:
        decoder = decoder_cls(dirs)
    except Exception as e:
        eprint(f"Failed to initialize decoder {decoder_cls.__name__}:")
        print_exception(e)
        return False
    try:
        decoder.eprint("Try decoding...")
        output_chunks = decoder.decode(ignore_mac_error)
        n_chunks = 0
        with open_output(out_file) as f:
            for chunk in output_chunks:
                if chunk:
                    f.write(chunk)
                    n_chunks += 1
            f.flush()
            if out_file:  # then f is not sys.stdout.buffer, so we can fsync
                os.fsync(f.fileno())
        if n_chunks > 0:
            if verbose():
                decoder.eprint("Successfully decoded!")
            return (True, verbose())  # success, print messages in verbose mode
        else:
            decoder.eprint("Produced no output.")
    except MacWarning:
        decoder.eprint(
            "WARNING: Decoded entire input, but unable to verify authenticity "
            "of output. Inputs may have been tampered with!")
        if verbose():
            traceback.print_exc()
        return (True, True)  # success, do print errors
    except Exception as e:
        decoder.eprint("Failed to decode with:")
        print_exception(e)
    return False


def do_combine(dirs, out_file, input_format='ALL', ignore_mac_error=False):
    decoders = DECODERS[input_format]
    print_errors = True
    if verbose():
        # Don't interfere with stderr
        cm = contextlib.nullcontext(None)
    else:
        # Suppress stderr, only print it if none of the decoders are
        # successful.
        cm = contextlib.redirect_stderr(io.StringIO())
    try:
        with cm as captured_err:
            loop_msg = ""
            for decoder_cls in decoders:
                if loop_msg:
                    eprint(loop_msg)
                ret = try_decode(decoder_cls, dirs, out_file, ignore_mac_error)
                if ret:
                    _, print_errors = ret
                    if hasattr(os, 'sync'):
                        os.sync()
                    return True
                loop_msg = "Trying next decoder."
    finally:
        if print_errors and hasattr(captured_err, 'getvalue'):
            err = captured_err.getvalue()
            if err:
                eprint(err, end='')

    raise RuntimeError(f"Unable to decode data in {iter_str(dirs)}.")


def try_identify(decoder_cls, dirs):
    try:
        decoder = decoder_cls(dirs)
    except Exception as e:
        print(f"Failed to initialize decoder {decoder_cls.__name__}:")
        print_exception(e, file=sys.stdout)
        return False
    reporter = Reporter(decoder)
    try:
        if reporter.identify():
            return True
    except Exception as e:
        print(f"{decoder.name}: And failed to identify with:")
        print_exception(e, file=sys.stdout)
    return False


def do_identify(dirs, input_format='ALL'):
    decoders = DECODERS[input_format]
    for decoder_cls in decoders:
        if try_identify(decoder_cls, dirs):
            return True
        print("Trying next decoder.")
    raise RuntimeError(f"Unable to identify all data in {iter_str(dirs)}.")
