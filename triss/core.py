import sys
import os
import tempfile



# Size of fragment chunks to decode at once.
CHUNK_SIZE = 4096
DEFAULT_FORMAT='DATA'


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class FatalError(Exception):
    pass





def read_buffered(fd, fail_empty=None):
    chunk = fd.read1()
    if fail_empty and not chunk:
        raise FatalError(fail_empty)
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



def ensure_splits_merge(datasets):
    for dataset in datasets:
        dirs = dataset['share_dirs']
        with tempfile.NamedTemporaryFile() as f:
            os.chmod(f.name, 0o600)
            merge_ret = do_merge(dirs, f.name, quiet=True)
            if merge_ret != 0:
                ds_id = dataset['dataset_id']
                raise FatalError(f"Failed to merge dataset {ds_id} after "
                                 "split, something went wrong, aborting.")
    return 0


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
