import sys
import gzip
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
# | Header (9 bytes total)                                               |
# | Version | Flags  | Dataset ID | Fragment index | Number of fragments |
# | 1 byte  | 1 byte | 1 byte     | 1 byte         | 1 byte              |
#
# | Header, continued                   |                 | Data             |
# | Segment index  | Number of segments | Header checksum | GZipped data     |
# | 1 byte         | 1 byte             | 2 bytes         | 0 - 1268 bytes   |
#
# | Data                                                       |
# | Uncompressed or GZipped data                               |
# | 0 - 1265 bytes for QR code, or 0 - n bytes for .dat file   |
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

BUF_SIZE = 2
#BUF_SIZE = 1024

# From https://www.qrcode.com/en/about/version.html
QR_SIZE_BYTES = 1273
QR_HEADER_SIZE_BYTES = 7
QR_DATA_SIZE_BYTES = QR_SIZE_BYTES - QR_HEADER_SIZE_BYTES
QR_BOX_SIZE = 10
QR_BORDER = 5
MARGIN = QR_BOX_SIZE * QR_BORDER


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class FatalError(Exception):
    pass


def partition_all(n, xs):
    it = iter(xs)
    while True:
        chunk = list(itertools.islice(it, n))
        if not chunk:
            return
        yield chunk


def assert_byte(b, msg):
    if b < 0 or b > 255:
        raise FatalError(
            msg + " value '{}' is out of range, must be in [0,255].".format(b))


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
    FLAG_GZIP_COMPRESSION = 0x01

    fields = ['version', 'flags', 'dataset_id',
              'fragment_id', 'total_fragments',
              'segment_id', 'total_segments']

    def __init__(self, info):
        self.info = info

        flags = 0
        for f in self.info['flags']:
            flags &= f
        self.info['flags'] = f

        for f in self.fields:
            assert_byte(self.info[f], f)

        if self.info['fragment_id'] >= self.info['total_fragments']:
            raise FatalError(
                "fragment_id '{}' out of range, "
                "must be less than total_fragments '{}'".format(
                    self.info['fragment_id'],
                    self.info['total_fragments']))

        if self.info['segment_id'] >= self.info['total_segments']:
            raise FatalError(
                "segment_id '{}' out of range, "
                "must be less than total_segments '{}'".format(
                    self.info['segment_id'],
                    self.info['total_segments']))

    def to_bytes(self):
        data = bytes([self.info[f] for f in self.fields])
        return data + fletcher_checksum_16(data)

    @classmethod
    def from_info(cls, info):
        info['version'] = Header.VERSION
        return cls(info)

    @classmethod
    def parse(cls, data):
        flen = len(cls.fields)
        clen = 2
        if fletcher_checksum_16(data[0:flen]) != data[flen:flen+clen]:
            raise ValueError('checksum')
        info = {}
        for (i, f) in zip(range(flen), cls.fields):
            info[f] = data[i]

        (version, flags, dataset_id,
         fragment_id, total_fragments,
         segment_id, total_segments) = data[0:7]
        if version != cls.VERSION:
            raise ValueError('version')
        {'dataset_id': dataset_id,
         'fragment_id': fragment_id}


def xor_bytes(xs, ys):
    if len(xs) != len(ys):
        raise Exception("Refusing to xor byte strings of different length.")
    return bytes(b1 ^ b2 for b1, b2 in zip(xs, ys))


# return seq of chunks
# [[split0, split1, ..., splitn],
#  [split0, split1, ..., splitn],
#  ...]
def split_data_chunked(plain_data_chunks, n):
    n_pads = n - 1
    if n_pads < 1:
        raise FatalError(
            "Refusing to return plain_key_data without one-time padding. "
            "Check number of shares.")

    for plain_data in plain_data_chunks:
        data_len = len(plain_data)
        crypt_data = plain_data
        out_chunk = []
        for _ in range(n_pads):
            pad = secrets.token_bytes(data_len)
            out_chunk.append(pad)
            crypt_data = xor_bytes(crypt_data, pad)

        out_chunk.append(crypt_data)
        yield out_chunk


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
def m_of_n_shares(data, n, m):
    """
    Return iterator over sequence of (share_name, batch) tuples, where batch
    is an iterator over (info, data) tuples.
    """
    num_datasets = math.comb(n, m)    # n choose m
    dataset_ids = range(num_datasets)
    datasets = []
    for dataset_id in dataset_ids:
        datasets.append({'dataset_id': dataset_id,
                         'splits': split_data_chunked(data, m)})

    # Shares is (array) mapping that keeps track of which datasets belong to
    # each share:
    #   share_index -> [dataset_X, dataset_Y, ...]
    share_ids = range(n)
    # share_subset is the subset of size m of shares that include the dataset
    # named by dataset_id:
    for (dataset_id,
         share_subset) in zip(dataset_ids,
                              itertools.combinations(share_ids, m)):
        datasets[dataset_id]['share_ids'] = share_subset

    return (share_ids, datasets)


def dataset_chunks(dataset):
    data_chunks = iter(dataset['splits'])
    data_chunk0 = list(next(data_chunks))
    total_fragments = len(data_chunk0)
    if len(data_chunk0) != len(dataset['share_ids']):
        raise FatalError('fragment <-> share mapping is not 1-to-1.')
    header_chunk = [{'dataset_id': dataset['dataset_id'],
                     'fragment_id': fragment_id,
                     'total_fragments': total_fragments}
                    for fragment_id
                    in range(len(data_chunk0))]
    yield header_chunk
    yield data_chunk0
    for chunk in data_chunks:
        yield chunk


def share_name(share_id):
    return 'share-' + str(share_id)


def fragment_name(info):
    return 'data-{}_frag-{}'.format(
        info['dataset_id'],
        info['fragment_id']
    )


def write_dataset(dataset, default_info):
    # Pack data into one segment:
    default_info['segment_id'] = 0
    default_info['total_segments'] = 1

    chunks = dataset_chunks(dataset)
    header_chunk = next(chunks)

    if len(header_chunk) != len(dataset['share_dirs']):
        raise FatalError('fragment <-> share dir mapping is not 1-to-1.')

    fds = []
    for info, out_dir in zip(header_chunk, dataset['share_dirs']):
        info = {**default_info, **info}
        file_name = os.path.join(out_dir, fragment_name(info)) + ".dat"
        fd = open(file_name, 'wb')
        fds.append(fd)
        header = Header.from_info(info)
        fd.write(header.to_bytes())

    for dataset_chunk in chunks:
        for (fragment_chunk, fd) in zip(dataset_chunk, fds):
            fd.write(fragment_chunk)

    for fd in fds:
        fd.close()


def do_split(in_file_name, out_dir_path, fmt, n, m, is_gzip):
    if os.path.exists(out_dir_path):
        raise FatalError("Output dir {} already exists, aborting."
                         .format(out_dir_path))
    os.makedirs(out_dir_path)

    indata = None
    if in_file_name:
        with open(in_file_name, 'r') as f:
            indata = f.read()
    else:
        indata = sys.stdin.buffer.read()

    if is_gzip:
        indata = gzip.compress(indata)

    # TODO: read indata in chunks vs one giant [indata] chunk
    (share_ids, datasets) = m_of_n_shares([indata], n, m or n)

    share_dirs = {}
    for share in share_ids:
        share_dir = os.path.join(out_dir_path, share_name(share))
        share_dirs[share] = share_dir
        os.makedirs(share_dir)

    for dataset in datasets:
        dataset['share_dirs'] = [share_dirs[share_id]
                                 for share_id
                                 in dataset['share_ids']]

    info = {}
    if is_gzip:
        info['flags'] = [Header.FLAG_GZIP_COMPRESSION]

    if fmt == 'DATA':
        for dataset in datasets:
            write_dataset(dataset, info)
    elif fmt == 'QRCODE':
        None  # TODO
        # img = qr_image_with_caption(data,
        #                             info['caption'],
        #                             info.get('detail'))
        # img.save(out_path + '.png')
    else:
        raise FatalError("Invalid output format: {}".format(fmt))


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


def add_caption(img, title, body=None):
    w = img.size[0]
    h = 250
    capt = Image.new('RGB', (w, h), 'white')
    d = ImageDraw.Draw(capt)
    title_font = ImageFont.truetype('fonts/DejaVuSans.ttf', 36)
    d.line(((MARGIN, 200), (w - MARGIN, 200)), 'gray')
    d.text((w/2, 170), title, fill='black', font=title_font, anchor='md')
    if body:
        body_font = ImageFont.truetype('fonts/DejaVuSans.ttf', 12)
        d.text((w/2, 185), title, fill='black', font=body_font, anchor='md')

    return merge_img_y(capt, img)


def qr_image_with_caption(data, caption, body=None):
    img = qr_image(data)
    return add_caption(img, caption, body)


def partition_data(data):
    return partition_all(QR_DATA_SIZE_BYTES, data)


def qr_image_set(qrdata, caption=None):
    batches = partition_data(qrdata)
    images = []
    for (i, batch) in enumerate(batches):
        images += [qr_image(batch)]
        if caption:
            text = '{} - part {} of {}'.format(caption, i + 1, len(batches))
            images[i] = add_caption(images[i], text)
    return images






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
            do_split(args.i, args.out_dir, args.f, args.n, args.m, args.z)
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
