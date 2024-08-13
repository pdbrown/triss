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
    'DATA': [("FileDecoder", data_file.decoder)],
    'QRCODE': [("QRDecoder", qrcode.decoder)],
    'GUESS': [("FileDecoder", data_file.decoder),
              ("QRDecoder", qrcode.decoder)]
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
    bs_x = resize_seqs(BUFFER_SIZE, bs_x)
    bs_y = resize_seqs(BUFFER_SIZE, bs_y)

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
    if Path(out_dir).exists():
        raise RuntimeError(
            f"Output directory {out_dir} exists already. Aborting.")
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


def try_decode(decoder, out_file, ignore_mac_error):
    """
    Try to decode. Return False on error, or tuple of (True, print_errors)

    where print_errors is a boolean.
    """
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
                decoder.eprint("Decoding successful!")
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


def do_combine(dirs,
               out_file,
               input_format='GUESS',
               scan_qr=False,
               ignore_mac_error=False):
    decoders = DECODERS[input_format]
    print_errors = True
    if verbose() or scan_qr:
        # Don't interfere with stderr
        cm = contextlib.nullcontext(None)
    else:
        # Suppress stderr, only print it if none of the decoders are
        # successful.
        cm = contextlib.redirect_stderr(io.StringIO())
    try:
        with cm as captured_err:
            loop_msg = ""
            for name, decoder_fn in decoders:
                if loop_msg:
                    eprint(loop_msg)
                try:
                    decoder = decoder_fn(dirs, name=name, scanner=scan_qr)
                except Exception as e:
                    eprint(f"Failed to initialize {name}:")
                    print_exception(e)
                    loop_msg = "Trying next decoder."
                    continue

                ret = try_decode(decoder, out_file, ignore_mac_error)
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

    err = "Unable to decode data"
    if dirs:
        err += f" in {iter_str(dirs)}"
    raise RuntimeError(err)


def try_identify(decoder):
    reporter = Reporter(decoder)
    try:
        if reporter.identify():
            return True
    except Exception as e:
        print(f"{decoder.name}: And failed to identify with:")
        print_exception(e)
    return False


def do_identify(dirs, input_format='GUESS', scan_qr=False):
    decoders = DECODERS[input_format]
    loop_msg = ""
    for name, decoder_fn in decoders:
        if loop_msg:
            eprint(loop_msg)
        try:
            decoder = decoder_fn(dirs, name=name, scanner=scan_qr)
        except Exception as e:
            eprint(f"Failed to initialize {name}:")
            print_exception(e)
            loop_msg = "Trying next decoder."
            continue
        if try_identify(decoder):
            return True
        loop_msg = "Trying next decoder."

    err = "Unable to identify all data"
    if dirs:
        err += f" in {iter_str(dirs)}"
    raise RuntimeError(err)
