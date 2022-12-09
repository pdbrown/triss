import sys
import gzip
import zlib
import os
import math
import argparse
import itertools
import secrets

import qrcode
from PIL import Image, ImageDraw, ImageFont


# Data layout:
# Largest QR code (size/version "40") can hold 1273 bytes of data in maximum
# error correction mode. Reserve first k bytes for header, rest for data.
# If output is to a .dat files instead, each fragment is packed into a single
# segment of unlimited size (see also 'Detailed steps' below).
#
# | Header (20 bytes total)                                         |
# | Version | Flags   | Dataset ID | Fragment index | Segment index |
# | 2 byte  | 4 bytes | 4 bytes    | 4 bytes        | 4 bytes       |
#
# | Header          | Data                                                   |
# | Header checksum | Uncompressed or GZipped data                           |
# | 2 bytes         | 0 - 1253 bytes for QR code, else .dat file 0 - n bytes |
#
#
# Data split algorithm overview:
# Input data is split using a "trivial secret sharing" algorithm.
# See https://en.wikipedia.org/wiki/Secret_sharing#Trivial_secret_sharing
# Input data is compressed with gzip, split into fragments by XOR with
# one-time pads, and broken into segments, each of which fits into a QR code.
#
#
# Detailed steps:
# - Compress input with gzip.
# - Let n be the number of shares needed to reconstruct the input.
# - Generate n-1 one-time pads (otp_1 through otp_(n-1)). A one-time pad is a
#   cryptographically secure (i.e. unguessable) random string of bits of same
#   length as the original data (length of the compressed input in this case).
# - Return the result of XOR(compressed_data, otp_1, ..., otp_(n-1)) as the
#   first fragment and the one-time pads as remaining fragments for a total of
#   n fragments.
# - Break each fragment into segments:
#   - If output is QR code format: break each fragment into 1266 byte
#     "segments". A segment fits into a QR code (1273 bytes max = 9 bytes
#     header + up to 1264 bytes data).
#   - If output is .dat file format, leave the fragment whole, as a single
#     segment.
# For each segment:
# - Construct 9 byte header:
#   - Field 1 holds the version of this program used to write the file.
#   - Field 2 holds a set of bit flags, e.g. whether data is compressed with
#     gzip.
#   - Field 3 is the "Dataset ID", which identifies a set of fragments
#     which, when combined, can reproduce the original input.
#   - Fields 4 and 5 identify the fragment (by 0-based index) and specify total
#     number of fragments, e.g.:
#       Field 4, share index: 0
#       Field 5, num shares:  3
#     means this is the first of 3 total shares.
#   - Fields 6 and 7 identify the segment (by 0-based index) and total number
#     of segments.
#       Field 6, segment index: 1
#       Field 7, num segment:   2
#     means this is the second (last) of 2 total segments.
#   - Fields 8 and 9 contain a checksum of all preceding header bytes.
# - Build the payload by concatenating header and data segment.
# - Write payload:
#   - To a QR code as PNG file, or
#   - As a binary .dat file.
#
#
# Data reconstruction algorithm:
# Given all output files obtained by running the split algorithm above:
# - Decode them:
#   - Decode QR codes into byte arrays, or
#   - Read byte arrays from .dat files.
# - Parse headers
#   - Validate their checksums.
#   - Assert their version fields match the version of this program.
# - Group segments by dataset id then fragment index.
# - Assert all segments of all fragments are available.
# - Concatenate each segment in order by index to obtain the fragment.
# - Combine the fragments with XOR to obtain the compressed input.
# - Decompress the input to obtain the original plaintext data.
#
#
# M-of-N shares:
# So far, data was split into N shares, each of which is needed to reconstruct
# the original. To split into M-of-N shares, so that data can be recovered with
# any M of N total shares, do an M-way split for each subset (size M) of N
# shares that should have access to the data: N choose M for a full M-of-N
# split.
# E.g. for 2-of-3 sharing: make 3 separate 2-of-2 splits, using a different
# dataset ID for each, say A, B, and C.
# Then choose pairs of fragments from each set (assuming 1 segment for this
# example), and bundle those into 3 shares, any 2 of which are enough to
# recover the original:
#
# share 1:  A1, B1
# share 2:  A2,     C1
# share 3:      B2, C2
#
# Or for 2-of-4 splits, make 6 2-of-2 splits and arrange as follows:
# share 1:  A1, B1, C1
# share 2:  A2,         D1, E1
# share 3:      B2,     D2,     F1
# share 4:          C2,     E2, F2
#
# This scheme becomes unwieldy for larger splits. For better M-of-N share
# algorithms consider:
# https://en.wikipedia.org/wiki/Secret_sharing#Efficient_secret_sharing


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class FatalError(Exception):
    pass


def fletcher_checksum_16(xs):
    """
    Return 2 byte fletcher's checksum.
    """
    c = 0
    n = 0
    for x in xs:
        n = (n + x)  # running sum, ignores order
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
    FLAG_LAST_FRAGMENT    = 0x00000100
    FLAG_LAST_SEGMENT     = 0x00000200

    @staticmethod
    def set_flag(info, flag):
        flags = info.setdefault('flags', set())
        flags.add(flag)

    def __init__(self, info):
        self.info = info

        flags = 0
        self.info['flags']
        for f in self.info.get('flags') or []:
            flags |= f
        self.info['flags'] = flags

        for (f, l) in self.FIELDS:
            self.field_bytes(f, l)

    def field_bytes(self, k, l):
        v = self.info.get(k) or 0
        return v.to_bytes(length=l, byteorder='big')

    def to_bytes(self):
        data = bytes(itertools.chain.from_iterable(
            [self.field_bytes(f, l)
             for (f, l)
             in self.FIELDS]))
        return data + fletcher_checksum_16(data)

    def test_flag(self, flag):
        return self.info['flags'] & flag != 0

    @classmethod
    def from_info(cls, info):
        info['version'] = Header.VERSION
        return cls(info)

    @classmethod
    def parse(cls, data):
        None
        # TODO
        # flen = len(cls.FIELDS)
        # clen = 2
        # if fletcher_checksum_16(data[0:flen]) != data[flen:flen+clen]:
        #     raise ValueError('checksum')
        # info = {}
        # for (i, f) in zip(range(flen), cls.FIELDS):
        #     info[f] = data[i]

        # (version, flags, dataset_id,
        #  fragment_id, total_fragments,
        #  segment_id, total_segments) = data[0:7]
        # if version != cls.VERSION:
        #     raise ValueError('version')
        # {'dataset_id': dataset_id,
        #  'fragment_id': fragment_id}


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

    crypt_data = plain_data
    for _ in range(n_pads):
        pad = os.urandom(len(plain_data))
        crypt_data = xor_bytes(crypt_data, pad)
        yield pad

    yield crypt_data


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
        infos.append({**common_info,
                      'fragment_id': fragment_id})
    Header.set_flag(infos[-1], Header.FLAG_LAST_FRAGMENT)
    return [Header.from_info(info) for info in infos]


def write_dat_datasets(datasets, input_chunks, info):
    for dataset in datasets:
        # Fit each fragment into exactly 1 segment:
        # Leave segment_id None (becomes 0), and set this to be the last
        # segment:
        Header.set_flag(info, Header.FLAG_LAST_SEGMENT)
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


def resize_chunks(size, chunk_seq):
    if size <= 0:
        raise Exception("size must be > 0")
    buf = []
    acc = 0
    def flush_one():
        nonlocal buf, acc
        avail = min(size, acc)
        buflen = len(buf)
        i = 0
        n = 0
        xs = []
        while n < avail and i < buflen:  # need more data
            xs += buf[i]
            n += len(buf[i])
            i += 1
        chunk = xs[0:avail] # chunk is ready
        # save any trailing data
        # i points to the element after the last one we need
        if n == avail:
            # Then there is no data left in the last chunk we pulled
            del buf[0:i]
        else:
            # Keep last slot we pulled to save remainder at front of buffer
            del buf[0:i-1]
            buf[0] = xs[-(n-avail):]
        acc -= avail
        return chunk

    for chunk in chunk_seq:
        # Collect chunks in intermediate buffer.
        buf.append(chunk)
        acc += len(chunk)
        # Flush buffer once we have enough chunks to make an output of size
        # `size`.
        while acc >= size:
            yield flush_one()

    if acc > 0:
        # flush last chunk if any, can be fewer than `size` bytes large
        yield flush_one()

    # Assert buffer really was flushed
    if buf:
        raise Exception("buf not empty at end of iteration, this is a bug.")


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
    input_segments = resize_chunks(QR_DATA_SIZE_BYTES, input_chunks)
    for (segment_id, (is_last, segment)) in enumerate(iter_islast(input_segments)):
        for dataset in datasets:
            share_size = dataset['share_size']  # number parts per share
            share_parts = dataset['share_parts']
            fragments = split_data(segment, dataset['num_fragments'])
            single_segment = segment_id == 0 and is_last
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


def read_buffered(fd):
    chunk = fd.read1()
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


def do_split(in_file_name, out_dir_path, fmt, n, m, do_gzip, secret_name):
    (share_ids, datasets) = m_of_n_shares(m or n, n)
    setup_share_dirs(share_ids, out_dir_path, datasets)

    header_info = {}
    if do_gzip:
        Header.set_flag(header_info, Header.FLAG_GZIP_COMPRESSION)

    (infd, do_close) = open_input(in_file_name)
    data_chunks = read_buffered(infd)
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


def files(dirs):
    for d in dirs:
        for f in os.listdir(d):
            if f.endswith('.png'):
                yield (f, 'QRCODE')
            elif f.endswith('.dat'):
                yield (f, 'DATA')


def decode_qr_code(path):
    bytes([])  # TODO


def read_file(path, typ):
    if typ == 'QRCODE':
        return decode_qr_code(path)
    elif typ == 'DATA':
        with open(path, 'rb') as f:
            return f.read()
    else:
        raise FatalError('')


def do_merge(dirs, out_file_name):
    1


# From https://www.qrcode.com/en/about/version.html
QR_SIZE_BYTES = 1273
QR_DATA_SIZE_BYTES = QR_SIZE_BYTES - Header.HEADER_SIZE_BYTES
QR_BOX_SIZE = 10
QR_BORDER = 5
MARGIN = QR_BOX_SIZE * QR_BORDER


def qr_image(qrdata):
    qr = qrcode.QRCode(
        # int in range [1,40] to determine size, set to None and use fit= to
        # determine automatically.
        version=None,
        # ERROR_CORRECT_H is maximum level ("high") of error correction: up to
        # 30% of lost data bytes can be recovered.
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=QR_BOX_SIZE,
        border=QR_BORDER,
    )

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
                   default='QRCODE',
                   help='output file format, defaults to QRCODE')
    s.add_argument('-t', type=str, required=False, default='Split Secret',
                   metavar='SECRET_NAME', help='name of secret to include on '
                   'QRCODE images')
    m = sp.add_parser('merge',
                      help='Merge shares and reconstruct original input.')
    m.add_argument('in_dirs', type=str, nargs='+',
                   metavar='DIR',
                   help='one or more directories containing qrcode images or .dat files to combine')
    m.add_argument('-o', type=str, nargs=1, required=False,
                   metavar='OUT_FILE',
                   help='write merged result to output file, '
                   'or stdout if omitted')

    args = parser.parse_args()
    try:
        if args.command == 'split':
            do_split(args.i, args.out_dir, args.f, args.n, args.m, args.z, args.t)
        elif args.command == 'merge':
            do_merge(args.in_dirs, args.o)
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
