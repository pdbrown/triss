from collections import defaultdict, namedtuple
from pathlib import Path
import os
import re
import sys
import tempfile

from triss.codec import data_file
try:
    from triss.codec import qrcode
    have_qrcode = True
except ModuleNotFoundError:
    have_qrcode = False

DEFAULT_FORMAT='DATA'
TRY_DECODERS = [data_file.FileDecoder]
if have_qrcode:
    TRY_DECODERS.append(qrcode.QRDecoder)

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

class FatalError(Exception):
    pass


def read_buffered(path):
    with path.open() as f:
        chunk = f.read1()
        while chunk:
            yield chunk
            chunk = fd.read1()

def list_files(dirs):
    """
    Yield seq of 'file infos': [{path, type} ...]
    """
    for d in dirs:
        for f in os.listdir(d):
            p = os.path.join(d, f)
            if f.endswith('.png'):
                yield {'path': p, 'type': 'QRCODE'}
            elif f.endswith('.dat'):
                yield {'path': p, 'type': 'DATA'}

def run_cmd(cmd, *args, **kwargs):
    for k in [k for (k, v) in kwargs.items() if v is None]:
        del kwargs[k]
    try:
        rc = cmd(*args, **kwargs)
    except FatalError as e:
        for arg in e.args:
            eprint(arg)
        return 1
    return rc


def do_split(in_file, out_dir,
             output_format=DEFAULT_FORMAT, n=2, m=2,
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
        check_asets_combine(in_file, out_dir, m)



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
        with Path(out_file).open('wb') as f:
            for chunk in output_chunks:
                if chunk:
                    f.write(chunk)
                    n_chunks += 1
        if n_chunks > 0:
            return True
    raise FatalError(f"Unable to decode data in {dirs}.")


def check_asets_combine(in_file, out_dir, m, input_format):
    with tempfile.TemporaryDirectory() as d:
        for share_dirs in data_file.authorized_share_sets(out_dir, m):
            f = Path(d) / "check_output"
            try:
                do_combine(share_dirs, f, input_format)
            except FatalError as e:
                for arg in e.args:
                    eprint(arg)
                raise FatalError(f"Failed to reproduce input combining shares "
                                 f"in {share_dirs}.")
