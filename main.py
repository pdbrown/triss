import sys
import gzip
import os
import qrcode
from PIL import Image, ImageDraw, ImageFont

# QR code data layout:
# | Header (5 bytes total)                                    |
# | Dataset ID | Data segment index | Number of data segments |
# | 1 byte     | 1 byte             | 1 byte                  |
#
# | Header, continued                    | Data               |
# | Fragment index | Number of fragments | GZipped data       |
# | 1 byte         | 1 byte              | 0 - 1268 bytes     |
#
# Data split algorithm:
# Input data is split using a "trivial secret sharing" algorithm.
# See https://en.wikipedia.org/wiki/Secret_sharing#Trivial_secret_sharing
# - Input data is compressed with gzip.
# - Compressed data is XORed with one-time-pads and packed into QR codes.
# - Largest QR code (size/version "40") can hold 1273 bytes of data.
# - Reserve first 5 bytes for header, rest for data.
# - Break data into "segments", each up to 1268 bytes (remaining QR code
#   capacity after header).
# - Split each segment into "number of fragments" many fragments, each of which
#   is needed to reconstruct the original segment.
#   - Generate num_fragments - 1 "one time pads" (otp_1 through otp_(n-1)). A
#     one time pad is a cryptographically secure random string of bits of same
#     length as the original data segment.
#   - Return the result of XOR(orig_data_segment, otp_1, ..., otp_(n-1))
#     as the first fragment, and all one time pads for a total of n fragments.
# - Prepend header to each generated fragment for each segment, and save it as
#   a QR code.
#   - The first header field, "Dataset ID", is used to group qr codes for which
#     segments and fragments all belong to the same original input.
#   - Fields 2 and 3 specify which segment this is, e.g.:
#     segment index 1, num segments 4, means this is the first of 4 total
#     segments.
#   - Fields 4 and 5 specify which fragment of the segment this is, e.g.:
#     fragment index 2, num fragments 2, means this is the second of 2 total
#     fragments.
#
# Data reconstruction algorithm:
# - Given all QR codes obtained by running the split algorithm above:
# - Decode QR codes.
# - Read the headers and arrange segments and fragments in order.
# - Assert all headers have the same dataset id.
# - Assert we have all "number of data segments" many data segments.
# - Assert we have all "number of fragments" many fragments for each segment.
# - For each segment, combine its fragments with XOR(frag_1, ..., frag_n) to
#   obtain the plain text segment.
# - In segment order, concatenate plain text segments to obtain gzipped
#   plaintext data.
# - Decompress the gzipped data to obtain the original plaintext.
#
# M-of-N splits:
# So far, data was split into N fragments, each of which is needed to
# reconstruct the original. To split into M-of-N fragments, so that data can be
# recovered with any M of N total fragments, do an M-way split for each subset
# of N that should have access to the data: N choose M for a full M-of-N split.
# E.g. for 2-of-3 splits: make 3 separate 2-of-2 splits, using a different
# dataset ID for each, say A, B, and C.
# Then choose pairs of fragments from each set (assume 1 segment), and bundle
# those into 3 fragment groups, any 2 of which are enough to recover the
# original:
# A1, B1
# A2, C1
# B2, C2
# Or for 2-of-4 splits, make 6 2-of-2 splits and arrange as follows:
# A1, B1, C1
# A2,         D1, E1
#     B2,     D2,     F1
#         C2,     E2, F2
# This scheme becomes unweildy for larger splits, but I wanted to keep it as
# simple as possible. For better M-of-N split algorithms see:
# https://en.wikipedia.org/wiki/Secret_sharing#Efficient_secret_sharing


# From https://www.qrcode.com/en/about/version.html
QR_SIZE_BYTES = 1273
QR_HEADER_SIZE_BYTES = 5
QR_DATA_SIZE_BYTES = QR_SIZE_BYTES - QR_HEADER_SIZE_BYTES
QR_BOX_SIZE = 10
QR_BORDER = 5
MARGIN = QR_BOX_SIZE * QR_BORDER


def partition_all(arr, step):
    if not arr:
        return []
    return [arr[:step]] + partition_all(arr[step:], step)


# From https://www.qrcode.com/en/about/version.html
MAX_BYTES_PER_QRCODE = 1273


def split_data(data):
    return partition_all(data, MAX_BYTES_PER_QRCODE)


def qr_image(qrdata):
    qr = qrcode.QRCode(
        # int in range [1,40] to determine size, set to None and use fit= to
        # determine automatically.
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )

    qr.add_data(qrdata)
    qr.make(fit=True)

    img = qr.make_image()
    return img


def all_qr_images(qrdata):
    return [qr_image(batch) for batch in split_data(qrdata)]


descriptor_file = sys.argv[1]
if descriptor_file:
    descriptors = open(descriptor_file, "rb")
else:
    descriptors = sys.stdin

gzdata = gzip.compress(descriptors.read())
images = all_qr_images(gzdata)


for i in range(len(images)):
    images[i].save("out{}.png".format(i))
