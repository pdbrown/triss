# About



# Setup

New setup
pip install --editable .
pip install --editable '.[qrcode]'
pip install --editable '.[test]'







To use a venv, run

"$(command -v python3 || command -v python)" -m venv venv
source venv/bin/activate

Now, un-suffixed commands are available: python, pip, etc

pip install -r requirements/common.txt


Deps: External `zbar` program is needed to decode QR codes.
Need version >= 0.23.1 released 2020-04-20 which has support for decoding
binary data from QR Code.
See also https://github.com/mchehab/zbar/tree/6092b033b35fdcc7ee95fc366ed303f475739bfc
- Linux:   sudo apt install zbar-tools
- MacOS:   brew install zbar
- Windows: ???
NOTE there is a library that could have worked, pyzbar, but it doesn't handle
binary qr codes properly.
See https://github.com/NaturalHistoryMuseum/pyzbar/pull/82

pip download 'qrcode[pil]'

pip install
Pillow-9.4.0-cp310-cp310-manylinux_2_28_x86_64.whl  qrcode-7.3.1.tar.gz  wheel-0.38.4-py3-none-any.whl


apt install zbar-tools

libzbar0
apt list libc6  libdbus-1-3  libjpeg8  libv4l-0 libx11-6

zbar-tools
libmagickwand-6.q16-6
 libmagickcore-6.q16-6
 imagemagick-6-common

apt-get download $(apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts --no-breaks --no-replaces --no-enhances zbar-tools | grep "^\w" | sort -u)

# Usage


# Algorithm

## Data layout
Largest QR code (size/version "40") can hold 1273 bytes of data in maximum
error correction mode. Reserve first k bytes for header, rest for data.
If output is to a .dat files instead, each fragment is packed into a single
segment of unlimited size (see also 'Detailed steps' below).

| Header (20 bytes total)                                         |
| Version | Flags   | Dataset ID | Fragment index | Segment index |
| 2 byte  | 4 bytes | 4 bytes    | 4 bytes        | 4 bytes       |

| Header          | Data                                                   |
| Header checksum | Uncompressed or GZipped data                           |
| 2 bytes         | 0 - 1253 bytes for QR code, else .dat file 0 - n bytes |


## Split input into multiple shares
Input data is split using a "trivial secret sharing" algorithm.
See https://en.wikipedia.org/wiki/Secret_sharing#Trivial_secret_sharing
Input data is compressed with gzip, split into fragments by XOR with
one-time pads, and broken into segments, each of which fits into a QR code.

**Detailed steps**
- Compress input with gzip.
- Let n be the number of shares needed to reconstruct the input.
- Generate n-1 one-time pads (otp_1 through otp_(n-1)). A one-time pad is a
  cryptographically secure (i.e. unguessable) random string of bits of same
  length as the original data (length of the compressed input in this case).
- Return the result of XOR(compressed_data, otp_1, ..., otp_(n-1)) as the
  first fragment and the one-time pads as remaining fragments for a total of
  n fragments.
- Break each fragment into segments:
  - If output is QR code format: break each fragment into 1266 byte
    "segments". A segment fits into a QR code (1273 bytes max = 9 bytes
    header + up to 1264 bytes data).
  - If output is .dat file format, leave the fragment whole, as a single
    segment.
For each segment:
- Construct 9 byte header:
  - Field 1 holds the version of this program used to write the file.
  - Field 2 holds a set of bit flags, e.g. whether data is compressed with
    gzip.
  - Field 3 is the "Dataset ID", which identifies a set of fragments
    which, when combined, can reproduce the original input.
  - Fields 4 and 5 identify the fragment (by 0-based index) and specify total
    number of fragments, e.g.:
      Field 4, share index: 0
      Field 5, num shares:  3
    means this is the first of 3 total shares.
  - Fields 6 and 7 identify the segment (by 0-based index) and total number
    of segments.
      Field 6, segment index: 1
      Field 7, num segment:   2
    means this is the second (last) of 2 total segments.
  - Fields 8 and 9 contain a checksum of all preceding header bytes.
- Build the payload by concatenating header and data segment.
- Write payload:
  - To a QR code as PNG file, or
  - As a binary .dat file.


## Merge shares to recover original data
Given all output files obtained by running the split algorithm above:
- Decode them:
  - Decode QR codes into byte arrays, or
  - Read byte arrays from .dat files.
- Parse headers
  - Validate their checksums.
  - Assert their version fields match the version of this program.
- Group segments by dataset id then fragment index.
- Assert all segments of all fragments are available.
- Concatenate each segment in order by index to obtain the fragment.
- Combine the fragments with XOR to obtain the compressed input.
- Decompress the input to obtain the original plaintext data.


## M-of-N shares
So far, data was split into N shares, each of which is needed to reconstruct
the original. To split into M-of-N shares, so that data can be recovered with
any M of N total shares, do an M-way split for each subset (size M) of N
shares that should have access to the data: N choose M for a full M-of-N
split.
E.g. for 2-of-3 sharing: make 3 separate 2-of-2 splits, using a different
dataset ID for each, say A, B, and C.
Then choose pairs of fragments from each set (assuming 1 segment for this
example), and bundle those into 3 shares, any 2 of which are enough to
recover the original:

share 1:  A1, B1
share 2:  A2,     C1
share 3:      B2, C2

Or for 2-of-4 splits, make 6 2-of-2 splits and arrange as follows:
share 1:  A1, B1, C1
share 2:  A2,         D1, E1
share 3:      B2,     D2,     F1
share 4:          C2,     E2, F2

This scheme becomes unwieldy for larger splits. For better M-of-N share
algorithms consider:
https://en.wikipedia.org/wiki/Secret_sharing#Efficient_secret_sharing
