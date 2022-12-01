import sys
import gzip
import os
import math
import argparse
import itertools
import qrcode
from PIL import Image, ImageDraw, ImageFont


# QR code data layout:
# Largest QR code (size/version "40") can hold 1273 bytes of data in maximum
# error correction mode. Reserve first 5 bytes for header, rest for data.
#
# | Header (5 bytes total)                      |
# | Dataset ID | Share index | Number of shares |
# | 1 byte     | 1 byte      | 1 byte           |
#
# | Header, continued                   | Data               |
# | Segment index  | Number of Segments | GZipped data       |
# | 1 byte         | 1 byte             | 0 - 1268 bytes     |
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
#   first share and the one-time pads as remaining sharesfor a total of n
#   shares.
# - Break each share into 1268 byte "segments". A segment fits into a QR code
#   (1273 bytes max = 5 bytes header + up to 1268 bytes data).
# For each segment:
# - Construct 5 byte header:
#   - The first header field, "Dataset ID", is given by user and used to group
#     qr codes for which segments and fragments all belong to the same original
#     input.
#   - Fields 2 and 3 identify the share (via 1-based index) and specify total
#     number of shares, e.g.:
#       Field 2, share index: 1
#       Field 3, num shares:  3
#     means this is the first of 3 total shares.
#   - Fields 4 and 5 identify the segment (via 1-based index) and total number
#     of segments.
#       Field 4, segment index: 2
#       Field 5, num segment:   2
#     means this is the second (last) of 2 total segments.
# - Put the header followed by the segment body into a QR code, and write it out
#   as a PNG file.
#
#
# Data reconstruction algorithm:
# Given all QR codes obtained by running the split algorithm above:
# - Decode QR codes into segments.
# - Group segments by dataset id then share index.
# - Assert all segments of all shares are available.
# - Concatenate each segment in order by index to obtain the share.
# - Combine the shares with XOR to obtain the compressed input.
# - Decompress the input to obtain the original plaintext data.
#
#
# M-of-N shares:
# So far, data was split into N shares, each of which is needed to reconstruct
# the original. To split into M-of-N shares, so that data can be recovered with
# any M of N total shares, do an M-way split for each subset of N shares that
# should have access to the data: N choose M for a full M-of-N split.
# E.g. for 2-of-3 sharing: make 3 separate 2-of-2 splits, using a different
# dataset ID for each, say A, B, and C.
# Then choose pairs of splits from each set (assuming 1 segment for this
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


# From https://www.qrcode.com/en/about/version.html
QR_SIZE_BYTES = 1273
QR_HEADER_SIZE_BYTES = 5
QR_DATA_SIZE_BYTES = QR_SIZE_BYTES - QR_HEADER_SIZE_BYTES
QR_BOX_SIZE = 10
QR_BORDER = 5
MARGIN = QR_BOX_SIZE * QR_BORDER


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class FatalError(Exception):
    pass


def partition_all(arr, step):
    if not arr:
        return []
    return [arr[:step]] + partition_all(arr[step:], step)


def split_data(data):
    return partition_all(data, QR_DATA_SIZE_BYTES)


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
    im = Image.new("RGB", (w, h), "white")
    im.paste(im_top)
    im.paste(im_bottom, (0, im_top.size[1]))
    return im


def add_caption(img, title, body=None):
    w = img.size[0]
    h = 250
    capt = Image.new("RGB", (w, h), "white")
    d = ImageDraw.Draw(capt)
    title_font = ImageFont.truetype("fonts/DejaVuSans.ttf", 36)
    d.line(((MARGIN, 200), (w - MARGIN, 200)), "gray")
    d.text((w/2, 170), title, fill="black", font=title_font, anchor="md")
    if body:
        body_font = ImageFont.truetype("fonts/DejaVuSans.ttf", 12)
        d.text((w/2, 185), title, fill="black", font=body_font, anchor="md")

    return merge_img_y(capt, img)


def qr_image_with_caption(data, caption, body=None):
    img = qr_image(data)
    return add_caption(img, caption, body)


def qr_image_set(qrdata, caption=None):
    batches = split_data(qrdata)
    images = []
    for i in range(len(batches)):
        images += [qr_image(batches[i])]
        if caption:
            text = "{} - part {} of {}".format(caption, i + 1, len(batches))
            images[i] = add_caption(images[i], text)
    return images


def xor_bytes(data_1, data_2):
    if len(data_1) != len(data_2):
        raise Exception("Refusing to xor byte strings of different length.")
    return bytes(b1 ^ b2 for b1, b2 in zip(data_1, data_2))


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


def fragment_name(info):
    return "data-{}_frag-{}".format(
        info['dataset_id'],
        info['fragment_id']
    )


def dataset_batch(name_prefix, datasets):
    for dataset in datasets:
        info = {'dataset_id': dataset['dataset_id'],
                'fragment_id': dataset['next']}
        fragment = next(dataset['splits'])
        dataset['next'] += 1
        yield (info, fragment)


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
                         'next': 0,
                         'splits': split_data(data, m)})

    # Shares is (array) mapping that keeps track of which datasets belong to
    # each share:
    #   share_index -> [dataset_X, dataset_Y, ...]
    share_ids = range(n)
    shares = [[] for _ in share_ids]
    # share_subset is the subset of size m of shares that include the dataset
    # named by dataset_id:
    for (dataset_id, share_subset) in zip(dataset_ids,
                                          itertools.combinations(share_ids, m)):
        for share in share_subset:
            shares[share].append(datasets[dataset_id])

    for share_id in range(n):
        share_name = "share-" + str(share_id)
        yield (share_name, dataset_batch(share_name, shares[share_id]))


def do_split(in_file_name, out_dir_path, fmt, n, m):
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

    gzdata = gzip.compress(indata)
    for (share_name, batch) in m_of_n_shares(gzdata, n, m or n):
        share_dir = os.path.join(out_dir_path, share_name)
        os.makedirs(share_dir)
        for (info, data) in batch:
            out_path = os.path.join(share_dir, fragment_name(info))
            if fmt == 'DATA':
                with open(out_path + ".dat", "wb") as f:
                    f.write(data)
            elif fmt == 'QRCODE':
                img = qr_image_with_caption(data,
                                            info['caption'],
                                            info.get('detail'))
                img.save(out_path + ".png")
            else:
                raise FatalError("Invalid output format: {}".format(fmt))


def do_merge(dir, out_file_name):
    1


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
    m.add_argument('in_dir', type=str, nargs=1,
                   metavar='DIR',
                   help='directory containing qr images to combine')
    m.add_argument('-o', type=str, nargs=1, required=False,
                   metavar='OUT_FILE',
                   help='write merged result to output file, '
                   'or stdout if omitted')

    args = parser.parse_args()
    try:
        if args.command == 'split':
            do_split(args.i, args.out_dir, args.f, args.n, args.m)
        elif args.command == 'merge':
            do_merge(args.in_dir, args.o)
        else:
            eprint("Invalid command: {}".format(args.command))
            return 1
    except FatalError as e:
        for arg in e.args:
            eprint(arg)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
