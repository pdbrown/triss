import sys
import gzip
import zlib
import os
import math
import argparse
import itertools
import secrets
import copy
import subprocess
import tempfile

import qrcode
from PIL import Image, ImageDraw, ImageFont


# Size of fragment chunks to decode at once.
CHUNK_SIZE = 4096
DEFAULT_FORMAT='DATA'


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class FatalError(Exception):
    pass


def fletchers_checksum_16(xs):
    """
    Return 2 byte fletcher's checksum.
    """
    c = 0
    n = 0
    for x in xs:
        n = (n + x)  # running sum, order independent
        c = (c + n)  # sum of running sums, depends on order
    return bytes([c % 255, n % 255])


class Header:
    VERSION = 1
    FIELDS = [['version', 2],
              ['flags', 4],
              ['dataset_id', 4],
              ['fragment_id', 4],
              ['segment_id', 4]]
    # Field bytes + 2 for checksum
    HEADER_SIZE_BYTES = sum(n for (f, n) in FIELDS) + 2

    FLAG_GZIP_COMPRESSION = 0x00000001
    FLAG_LAST_SEGMENT     = 0x00000100
    FLAG_LAST_FRAGMENT    = 0x00000200

    @staticmethod
    def set_flag(info, flag):
        flags = info.setdefault('flags', set())
        flags.add(flag)

    def __init__(self, info):
        self.info = info

        if not isinstance(self.info.get('flags'), int):
            flags = 0
            for f in self.info.get('flags') or []:
                flags |= f
            self.info['flags'] = flags

        for (f, l) in self.FIELDS:
            self.field_bytes(f, l)

    def field_bytes(self, k, l):
        v = self.info.get(k) or 0
        return v.to_bytes(length=l, byteorder='big', signed=False)

    def to_bytes(self):
        data = bytes(itertools.chain.from_iterable(
            [self.field_bytes(f, l)
             for (f, l)
             in self.FIELDS]))
        return data + fletchers_checksum_16(data)

    def test_flag(self, flag):
        return self.info['flags'] & flag != 0

    @classmethod
    def from_info(cls, info):
        info['version'] = Header.VERSION
        return cls(info)

    @classmethod
    def parse(cls, data):
        if len(data) < cls.HEADER_SIZE_BYTES:
            raise ValueError(f"Can't parse header, got {len(data)} bytes but "
                             f"needed at least {cls.HEADER_SIZE_BYTES} bytes.")
        data = data[0:cls.HEADER_SIZE_BYTES]
        checksum = bytes(data[-2:])  # last 2 bytes are checksum
        payload = bytes(data[0:-2])  # first n-2 bytes are payload
        if fletchers_checksum_16(payload) != checksum:
            raise ValueError("Refusing to parse header with bad checksum.")
        info = {}
        k = 0
        for (f, l) in cls.FIELDS:
            info[f] = int.from_bytes(payload[k:k+l], byteorder='big', signed='false')
            k += l

        if info['version'] != cls.VERSION:
            raise ValueError(f"Incompatible header version, got {info['version']}' "
                             f"but expected {cls.VERSION}")
        return cls.from_info(info)


def xor_bytes(xs, ys):
    if len(xs) != len(ys):
        raise Exception("Refusing to xor byte strings of different length.")
    return bytes(b1 ^ b2 for b1, b2 in zip(xs, ys))


def split_data(plain_data, n):
    n_pads = n - 1
    if n_pads < 1:
        raise FatalError(
            "Refusing to return plain_key_data without one-time padding. "
            "Check number of shares.")

    crypt_data = list(plain_data)
    k = len(crypt_data)
    for _ in range(n_pads):
        pad = secrets.token_bytes(k)
        crypt_data = xor_bytes(crypt_data, pad)
        yield pad

    yield crypt_data


def merge_data(fragments):
    it = iter(fragments)
    plain_data = next(it)
    for frag in it:
        plain_data = xor_bytes(plain_data, frag)
    return plain_data

# list(merge_data(split_data([0, 1, 2, 3, 4, 5, 6, 7, 8], 3)))


# m-of-n examples:
# 2-of-2:
# share 1: A1
# share 2: A2
#
# 2-of-3:
# share 1:  A1, B1
# share 2:  A2,     C1
# share 3:      B2, C2
#
# 2-of-4:
# ds_id #:   0,  1,  2,  3,  4,  5
# share 1:  A1, B1, C1
# share 2:  A2,         D1, E1
# share 3:      B2,     D2,     F1
# share 4:          C2,     E2, F2
def m_of_n_shares(m, n):
    """
    Return tuple of (share_ids, datasets), where share_ids number each share
    from 0 to n-1. The datasets output contains (n choose m) many datasets
    represented by dictionaries with keys:
      {dataset_id, num_fragments, share_ids, share_parts, share_size}
    dataset['share_ids'] : list
      is the subset of share_ids the dataset should be split among.
    dataset['share_parts'] : dict
      maps each share_id in this dataset to its share "part number" (1 based!)
    dataset['share_size'] : int
      number of datasets (i.e. fragments) shares consist of
    Consider 2-of-4 example above, dataset_id 0, share 2: has part #1 of share
    size 3.
    """
    num_datasets = math.comb(n, m)    # n choose m
    dataset_ids = range(num_datasets)
    datasets = []
    for dataset_id in dataset_ids:
        datasets.append({'dataset_id': dataset_id,
                         'num_fragments': m})

    share_ids = range(n)
    # share_subset is the subset of size m of shares that include the dataset
    # named by dataset_id:
    for (dataset_id,
         share_subset) in zip(dataset_ids,
                              itertools.combinations(share_ids, m)):
        datasets[dataset_id]['share_ids'] = share_subset

    set_share_part_nums(datasets, m, n, num_datasets)

    return (share_ids, datasets)


def set_share_part_nums(datasets, m, n, num_datasets):
    """
    m_of_n_shares fn helper. Use separate fn to avoid for-loop variable name collisions.
    """
    # Total number of fragments between all datasets
    total_fragments = num_datasets * m  # m fragments per dataset
    # Number of fragments (i.e. datasets) in each share
    share_size = int(total_fragments / n)  # n shares
    # Build share_parts mapping for each dataset: tells which part of a share
    # each fragment is.
    datasets_by_share = {}
    for dataset in datasets:
        for share_id in dataset['share_ids']:
            ds = datasets_by_share.setdefault(share_id, [])
            ds.append(dataset)
        dataset['share_size'] = share_size
    for (share_id, datasets) in datasets_by_share.items():
        for (part_i, dataset) in enumerate(datasets):
            share_parts = dataset.setdefault('share_parts', {})
            share_parts[share_id] = part_i + 1


def share_name(share_id):
    return 'share-' + str(share_id)


def fragment_name(info):
    fragment = f"data-{info['dataset_id']}_fragment-{info['fragment_id']}"
    if 'segment_id' in info:
        return fragment + f"_segment-{info['segment_id']}"
    else:
        return fragment


def dataset_headers(dataset, default_info):
    num_fragments = dataset['num_fragments']
    common_info = {**default_info,
                   'dataset_id': dataset['dataset_id']}
    infos = []
    for fragment_id in range(num_fragments):
        infos.append(copy.deepcopy({**common_info,
                                    'fragment_id': fragment_id}))
    Header.set_flag(infos[-1], Header.FLAG_LAST_FRAGMENT)
    return [Header.from_info(info) for info in infos]


def write_dat_datasets(datasets, input_chunks, info):
    # Fit each fragment into exactly 1 segment:
    # Leave segment_id None (becomes 0), and set this to be the last
    # segment:
    Header.set_flag(info, Header.FLAG_LAST_SEGMENT)
    for dataset in datasets:
        headers = dataset_headers(dataset, info)
        fds = []
        for header, out_dir in zip(headers, dataset['share_dirs']):
            file_name = os.path.join(out_dir, fragment_name(header.info)) + ".dat"
            fd = open(file_name, 'wb')
            fds.append(fd)
            fd.write(header.to_bytes())
        dataset['fds'] = fds

    for chunk in input_chunks:
        for dataset in datasets:
            fragments = split_data(chunk, dataset['num_fragments'])
            for fd, fragment in zip(dataset['fds'], fragments):
                fd.write(fragment)

    for dataset in datasets:
        for fd in dataset['fds']:
            fd.close()


def flush_bytes(buf, size, n):
    """
    Remove up to first N bytes from BUF. BUF is a list of byte strings, and
    SIZE is total number of bytes in BUF.
    Return (chunk, buf, size).
    - chunk is first n bytes of buf.
    - buf is same BUF reference. The first n bytes have been removed in place.
    - new size.
    """
    if n < 0:
        raise Exception("n must be >= 0")
    avail = min(n, size)
    buflen = len(buf)
    i = 0
    k = 0
    xs = b''
    while k < avail and i < buflen:  # get more data
        xs += buf[i]
        k += len(buf[i])
        i += 1
    chunk = xs[0:avail] # chunk is ready
    # save any trailing data
    # i points to the element after the last one we need
    if k == avail:
        # Then there is no data left in the last chunk we pulled
        del buf[0:i]
    else:
        # Keep last slot we pulled to save remainder at front of buffer
        del buf[0:i-1]
        buf[0] = xs[-(k-avail):]
    size -= avail
    return (chunk, buf, size)


def resize_chunks(chunk_seq, chunk_size):
    if chunk_size <= 0:
        raise Exception("chunk_size must be > 0")
    buf = []
    acc = 0

    for chunk in chunk_seq:
        # Collect chunks in intermediate buffer.
        if chunk:  # skip empty chunks
            buf.append(chunk)
        acc += len(chunk)
        # Flush buffer once we have enough chunks to make an output of size
        # `chunk_size`.
        while acc >= chunk_size:
            (chunk, buf, acc) = flush_bytes(buf, acc, chunk_size)
            yield chunk

    if acc > 0:
        # flush last chunk if any, can be fewer than `chunk_size` bytes large
        (chunk, buf, acc) = flush_bytes(buf, acc, chunk_size)
        yield chunk

    # Assert buffer really was flushed
    if buf:
        raise Exception("buf not empty at end of iteration, this is a bug.")


def skip_bytes(chunk_seq, n):
    it = iter(chunk_seq)
    buf = []
    acc = 0
    try:
        while acc < n:
            chunk = next(it)
            buf.append(chunk)
            acc += len(chunk)
    except StopIteration:
        return
    (_, buf, _) = flush_bytes(buf, acc, n)
    for chunk in itertools.chain(buf, it):
        yield chunk


def iter_islast(xs):
    it = iter(xs)
    try:
        x = next(it)
    except StopIteration:
        return
    while True:
        try:
            y = next(it)
            yield (False, x)
            x = y
        except StopIteration:
            yield (True, x)
            break


def write_qr_datasets(datasets, input_chunks, header_info, secret_name):
    input_segments = resize_chunks(input_chunks, QR_DATA_SIZE_BYTES)
    for (segment_id, (is_last, segment)) in enumerate(iter_islast(input_segments)):
        for dataset in datasets:
            share_size = dataset['share_size']  # number parts per share
            share_parts = dataset['share_parts']
            fragments = split_data(segment, dataset['num_fragments'])
            single_segment = segment_id == 0 and is_last
            header_info = copy.deepcopy(header_info)
            if not single_segment:
                header_info = {**header_info, 'segment_id': segment_id}
            if is_last:
                Header.set_flag(header_info, Header.FLAG_LAST_SEGMENT)
            headers = dataset_headers(dataset, header_info)
            for header, fragment, out_dir, share_id in \
                    zip(headers,
                        fragments,
                        dataset['share_dirs'],
                        dataset['share_ids']):
                out_path = os.path.join(out_dir, fragment_name(header.info)) + ".png"
                caption = f"{secret_name} - share {share_id}"
                if not single_segment:
                    segment_desc = f", segment {segment_id}"
                    if segment_id == 0:
                        segment_desc += " (first segment)"
                    elif is_last:
                        segment_desc += " (last segment)"
                else:
                    segment_desc = ""
                subtitle = f"Part {dataset['share_parts'][share_id]} " \
                    f"of {dataset['share_size']}" + segment_desc
                img = qr_image_with_caption(header.to_bytes() + fragment,
                                            caption,
                                            subtitle=subtitle)
                img.save(out_path)


def read_buffered(fd, fail_empty=None):
    chunk = fd.read1()
    if fail_empty and not chunk:
        raise FatalError(fail_empty)
    while chunk:
        yield chunk
        chunk = fd.read1()


def gzip_seq(chunk_seq):
    gz = zlib.compressobj(level=9)
    for chunk in chunk_seq:
        z = gz.compress(chunk)
        if z:
            yield z
    yield gz.flush()


def gunzip_seq(chunk_seq):
    gz = zlib.decompressobj()
    for chunk in chunk_seq:
        z = gz.decompress(chunk)
        if z:
            yield z
    yield gz.flush()


def open_input(file_name):
    infd = None
    closefds = []
    if file_name:
        infd = open(file_name, 'rb')
        closefds.append(infd)
    else:
        infd = sys.stdin.buffer

    def do_close():
        for fd in closefds:
            fd.close()

    return (infd, do_close)


def setup_share_dirs(share_ids, out_dir_path, datasets):
    if os.path.exists(out_dir_path):
        raise FatalError("Output dir {} already exists, aborting."
                         .format(out_dir_path))
    os.makedirs(out_dir_path)

    share_dirs = {}
    for share in share_ids:
        share_dir = os.path.join(out_dir_path, share_name(share))
        share_dirs[share] = share_dir
        os.makedirs(share_dir)

    for dataset in datasets:
        dataset['share_dirs'] = [share_dirs[share_id]
                                 for share_id
                                 in dataset['share_ids']]


def do_split(in_file_name, out_dir_path,
             fmt=DEFAULT_FORMAT, n=2, m=2, do_gzip=False,
             secret_name=None, skip_merge_check=False):
    if m < 2:
        raise FatalError("Must split into at least 2 shares.")
    if m > n:
        raise FatalError("N must be equal or greater than M for M-of-N split.")

    (share_ids, datasets) = m_of_n_shares(m or n, n)
    setup_share_dirs(share_ids, out_dir_path, datasets)

    header_info = {}
    if do_gzip:
        Header.set_flag(header_info, Header.FLAG_GZIP_COMPRESSION)

    (infd, do_close) = open_input(in_file_name)
    data_chunks = read_buffered(
        infd,
        fail_empty="Input is empty, nothing to do, aborting.")
    if do_gzip:
        data_chunks = gzip_seq(data_chunks)
    try:
        if fmt == 'DATA':
            write_dat_datasets(datasets, data_chunks, header_info)
        elif fmt == 'QRCODE':
            write_qr_datasets(datasets, data_chunks, header_info, secret_name)
        else:
            raise FatalError("Invalid output format: {}".format(fmt))
    finally:
        do_close()
    if not skip_merge_check:
        ensure_splits_merge(datasets)
    return 0



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


def open_dat_or_qrcode(finfo):
    """
    Return pair of (buffered_seq, do_close). do_close is 0 arg fn to call to
    release underlying resources.
    """
    if finfo['type'] == 'QRCODE':
        return (iter([decode_qr_code(finfo['path'])]), lambda : None)
    elif finfo['type'] == 'DATA':
        (infd, do_close) = open_input(finfo['path'])
        return (read_buffered(infd), do_close)
    else:
        raise FatalError(f"Unknown file type for finfo {finfo}")


def decode_headers(finfos):
    for finfo in finfos:
        (data, do_close) = open_dat_or_qrcode(finfo)
        try:
            header_chunk = next(resize_chunks(data, Header.HEADER_SIZE_BYTES))
            finfo['header'] = Header.parse(header_chunk)
            yield finfo
        except StopIteration:
            eprint(f"Failed to read file at {finfo['path']}, skipping it.")
        except ValueError as e:
            eprint(f"Failed to decode header from file at {finfo['path']}, "
                   f"skipping: {str(e)}")
        finally:
            do_close()


def find_dataset_parts(finfos, quiet=False):
    """
    Find first complete dataset among files described by FINFOS.
    Return a list of segment fragement collections. Each element of the outer
    list is the collection of fragments to combine to reconstruct the original
    segment.
    E.g.:
    [[seg0_frag0, seg0_frag1, ...],
     [seg1_frag0, seg1_frag1, ...],
     ...]
    """
    # Declare helpers first
    indent = 0
    def iprint(*objects, **kwargs):
        nonlocal indent
        if not quiet:
            print(" "*indent, *objects, sep='', **kwargs)

    def with_indent(i):
        def set_indent(f):
            def wrapper(*args, **kwargs):
                try:
                    nonlocal indent
                    prev = indent
                    indent = i
                    return f(*args, **kwargs)
                finally:
                    indent = prev
            return wrapper
        return set_indent

    @with_indent(4)
    def ok_parts_by_id(xs_by_id, is_last_part, name):
        if not xs_by_id:
            iprint(f"Found no {name}s.")
            return False
        n_parts = len(xs_by_id)
        iprint(f"Got {n_parts} {name}s, ensure contiguous ids from 0 to "
               f"{n_parts - 1}.")
        for i in range(n_parts):
            if i not in xs_by_id:
                iprint(f"Missing {name} at id {i}, "
                       f"expected to find {name}s 0 through {n_parts - 1}.")
                return False
        # Check no parts are missing past end of available parts
        iprint(f"Ensure set of {name}s is complete.")
        last_part = xs_by_id[n_parts - 1]
        is_last = is_last_part(last_part)
        if not is_last:
            iprint(f"Last {name} found didn't have 'last' flag set, missing "
                   f"{name}s after {name}_id {n_parts - 1}.")
        return is_last

    @with_indent(6)
    def is_last_seg(seg):
        if not seg:
            iprint("No segment supplied to check if it was last one.")
            return False
        for frag_id, frag in seg.items():
            if not frag['header'].test_flag(Header.FLAG_LAST_SEGMENT):
                iprint(f"Fragment {frag_id} of segment {seg['header'].info} "
                       "was not marked as belonging to last segment.")
                return False
        return True

    @with_indent(6)
    def is_last_frag(frag):
        if not frag:
            iprint("No fragment supplied to check if it was last.")
            return False
        is_last = frag['header'].test_flag(Header.FLAG_LAST_FRAGMENT)
        if not is_last:
            iprint(f"Fragment {frag['header'].info} was not marked as "
                   "'last fragment'.")
        return is_last

    @with_indent(2)
    def is_dataset_complete(dataset):
        iprint("Ensure all segments are available.")
        if not ok_parts_by_id(dataset, is_last_seg, "segment"):
            return False
        # Check all fragments are available in each segment:
        for (seg_id, seg) in dataset.items():
            iprint(f"Ensure all fragments of segment {seg_id} are available.")
            if not ok_parts_by_id(seg, is_last_frag, "fragment"):
                return False
        # Check all segments have same number of fragments:
        seg_size = len(next(iter(dataset.values())))
        for (seg_id, seg) in dataset.items():
            if len(seg) != seg_size:
                iprint(f"Expected each segment to have {seg_size} segments, "
                       f"but segment {seg_id} had {len(seg)} fragments.")
                return False
        return True

    @with_indent(2)
    def is_dataset_consistent(dataset):  # assumes dataset is complete
        # Assert all fragments of each segment have same gzip flag value within
        # the segment.
        for (seg_id, seg) in dataset.items():
            seg_gzipped = seg[0]['header'].test_flag(
                Header.FLAG_GZIP_COMPRESSION)
            for (frag_id, frag) in seg.items():
                frag_gzipped = frag['header'].test_flag(
                    Header.FLAG_GZIP_COMPRESSION)
                if frag_gzipped != seg_gzipped:
                    iprintf(f"Segment {seg_id} fragment {frag_id} had "
                            f"unexpected gzip flag. Expected {seg_gzipped} "
                            f" but got {frag_gzipped}. Flag must be the same "
                            "for all fragments.")
                    return False
        return True

    # Begin top level `find_dataset_parts` fn:
    # ds is datasets by dataset_id
    ds = group_finfos_by_dataset(finfos)
    out_dataset = None
    iprint("Looking for complete dataset among inputs.")
    for (dataset_id, dataset) in ds.items():
        iprint(f"Check dataset {dataset_id}.")
        if is_dataset_complete(dataset):
            iprint(f"Found complete dataset with id {dataset_id}!")
            if is_dataset_consistent(dataset):
                out_dataset = dataset
                break
            else:
                iprint(f"Dataset with id {dataset_id} is not consistent, "
                       "won't use it.")
    if not out_dataset:
        iprint("Failed to find a complete dataset among inputs, can't proceed.")
        return None
    return to_dataset_parts(out_dataset)


def group_finfos_by_dataset(finfos):
    ds = {}  # datasets by dataset_id
    for finfo in finfos:
        header = finfo['header']
        dataset = ds.setdefault(header.info['dataset_id'], {})
        segment = dataset.setdefault(header.info['segment_id'], {})
        segment[header.info['fragment_id']] = finfo
    return ds


def to_dataset_parts(dataset_dict):
    parts = []
    n_segments = len(dataset_dict[0])
    for seg_id in range(len(dataset_dict)):
        seg = dataset_dict[seg_id]
        frags = []
        for frag_id in range(len(seg)):
            frag = seg[frag_id]
            frags.append(frag)
        parts.append(frags)
    return parts


def fragmented_chunks(fragment_finfos):
    open_frags = []
    for finfo in fragment_finfos:
        (data, do_close) = open_dat_or_qrcode(finfo)
        data = resize_chunks(data, CHUNK_SIZE)
        open_frags.append((data, do_close))
    try:
        while True:
            next_chunks = []
            for (data, _) in open_frags:
                next_chunks.append(next(data))
            yield next_chunks
    except StopIteration:
        return
    finally:
        for (_, do_close) in open_frags:
            do_close()


def merged_segments(fragmented_segments):
    """
    Take fragmented segments, merge fragments, return seq of segments.
    Fragments are byte sequences, in same order as returned by
    `find_dataset_parts`.
    [[seg0_frag0,   seg0_frag1,   ..., seg0_frag(k)],
     [seg1_frag0,   seg1_frag1,   ..., seg1_frag(k)],
     ...,
     [seg(n)_frag0, seg(n)_frag1, ..., seg(n)_frag(k)]]
    ->
    [seg0, seg1, ..., seg(n)]
    """
    for fragments in fragmented_segments:
        yield merge_data(fragments)


def merge_dataset_parts(dataset_parts, out_file_name):
    with open(out_file_name, 'wb') as f:
        for segment in dataset_parts:
            # Read each fragment of segment chunk-wise. The chunk size is
            # determined by underlying buffering (read1 or QR code size).
            # Takes one fragmented segment [frag0, frag1, ..., fragn] to a list
            # of fragmented chunks in same layout as fragmented segment:
            # -> [[frag0_chunk0, frag1_chunk0, ...],
            #     [frag0_chunk1, frag1_chunk1, ...],
            #     ...]
            xs = fragmented_chunks(segment)
            # Merge each chunk of fragments into a plaintext chunk. (Same as
            # merging segments.)
            # -> [chunk0, chunk1, ..., chunk(n)]
            xs = merged_segments(xs)
            # Skip header, seek to data.
            xs = skip_bytes(xs, Header.HEADER_SIZE_BYTES)
            # Check header of first fragment for gzip flag.
            do_gunzip = segment[0]['header'].test_flag(
                Header.FLAG_GZIP_COMPRESSION)
            if do_gunzip:
                # Gunzip data stream
                xs = gunzip_seq(xs)
            for chunk in xs:
                f.write(chunk)


# Find files.
# Look for DATA format first, then QRCODE.
# DATA files: open fds, decode headers, assemble dataset, decode data.
# QRCODE files: decode all qrcodes in memory, decode headers, assemble
# dataset. Then decode qrcodes in dataset again, decode data.
def do_merge(dirs, out_file_name, quiet=False):
    finfos = decode_headers(list_files(dirs))
    dataset_parts = find_dataset_parts(finfos, quiet=quiet)
    if not dataset_parts:
        return 1
    if not dataset_parts:
        return None
    merge_dataset_parts(dataset_parts, out_file_name)
    return 0


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


# From https://www.qrcode.com/en/about/version.html
QR_SIZE_BYTES = 1273
QR_DATA_SIZE_BYTES = QR_SIZE_BYTES - Header.HEADER_SIZE_BYTES
QR_BOX_SIZE = 10
QR_BORDER = 5
MARGIN = QR_BOX_SIZE * QR_BORDER


def qr_image(data):
    qr = qrcode.QRCode(
        # int in range [1,40] to determine size, set to None and use fit= to
        # determine automatically.
        version=None,
        # ERROR_CORRECT_H is maximum level ("high") of error correction: up to
        # 30% of lost data bytes can be recovered.
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=QR_BOX_SIZE,
        border=QR_BORDER
    )
    qrdata = qrcode.util.QRData(data,
                                mode=qrcode.util.MODE_8BIT_BYTE,
                                check_data=False)
    qr.add_data(qrdata)
    qr.make(fit=True)
    img = qr.make_image()
    return img


def merge_img_y(im_top, im_bottom):
    w = max(im_top.size[0], im_bottom.size[0])
    h = im_top.size[1] + im_bottom.size[1]
    im = Image.new('RGB', (w, h), 'white')
    im.paste(im_top)
    im.paste(im_bottom, (0, im_top.size[1]))
    return im


def add_caption(img, title, subtitle=None):
    w = img.size[0]
    h = 200
    capt = Image.new('RGB', (w, h), 'white')
    d = ImageDraw.Draw(capt)
    title_font = ImageFont.truetype('fonts/DejaVuSans.ttf', 24)
    d.line(((MARGIN, 180), (w - MARGIN, 180)), 'gray')
    d.text((w/2, 150), title, fill='black', font=title_font, anchor='md')
    if subtitle:
        body_font = ImageFont.truetype('fonts/DejaVuSans.ttf', 12)
        d.text((w/2, 170), subtitle, fill='black', font=body_font, anchor='md')

    return merge_img_y(capt, img)


def qr_image_with_caption(data, caption, subtitle=None):
    img = qr_image(data)
    return add_caption(img, caption, subtitle)


def decode_qr_code(path):
    """
    Decode QR code in image at path PATH, return byte array.
    NOTE there must only be 1 QR code in the image! While zbarimg will decode
    multiple QR codes, in binary mode it concatenates their payloads, so
    there's no easy way to tell where one payload ends and the next begins
    """
    return subprocess.check_output(
        ['zbarimg', '--raw', '-Sbinary', path],
        stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description="""
    Trivial secret sharing utility.
    Split input into N-of-N or M-of-N shares or recover input from
    a set of shares.
    """)
    sp = parser.add_subparsers(help='x', dest='command', required=True)
    s = sp.add_parser('split', help='Split input into shares.')
    s.add_argument('n', type=int, metavar='N',
                   help='number of shares')
    s.add_argument('out_dir', type=str, metavar='DIR',
                   help='destination directory path')
    s.add_argument('-z', required=False, action='store_true',
                   help='Compress data with gzip before splitting')
    s.add_argument('-m', type=int,
                   help='integer M for M-of-N split: number of shares needed '
                   'to recover input if fewer than N')
    s.add_argument('-i', type=str, required=False,
                   metavar='IN_FILE', help='path to input file, '
                   'read from stdin if omitted')
    s.add_argument('-f', required=False, choices=['DATA', 'QRCODE'],
                   default=DEFAULT_FORMAT,
                   help='output file format, defaults to ' + DEFAULT_FORMAT)
    s.add_argument('-t', type=str, required=False, default='Split Secret',
                   metavar='SECRET_NAME', help='name of secret to include on '
                   'QRCODE images')
    s.add_argument('-k', required=False, action='store_true',
                   help='Skip merge check after splitting')
    m = sp.add_parser('merge',
                      help='Merge shares and reconstruct original input.')
    m.add_argument('in_dirs', type=str, nargs='+',
                   metavar='DIR',
                   help='one or more directories containing qrcode images or '
                   '.dat files to combine')
    m.add_argument('-o', type=str, required=False,
                   metavar='OUT_FILE',
                   help='write merged result to output file, '
                   'or stdout if omitted')

    args = parser.parse_args()
    try:
        if args.command == 'split':
            return do_split(args.i, args.out_dir, fmt=args.f,
                            n=args.n, m=args.m, do_gzip=args.z,
                            secret_name=args.t, skip_merge_check=args.k)
        elif args.command == 'merge':
            return do_merge(args.in_dirs, args.o)
        else:
            eprint('Invalid command: {}'.format(args.command))
            return 1
    except FatalError as e:
        for arg in e.args:
            eprint(arg)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
