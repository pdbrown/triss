from pathlib import Path
import re
import subprocess

import qrcode
from PIL import Image, ImageDraw, ImageFont

from triss import byte_seqs
from triss.codec import Header, TaggedDecoder
from triss.codecs.data_file import FileSegmentEncoder, FileDecoder


# From https://www.qrcode.com/en/about/version.html
# Set QR_SIZE_MAX_BYTES to be size of largest QR code with highest error
# correction enabled: Version 40, ECC level "H"
QR_SIZE_MAX_BYTES = 1273
# ERROR_CORRECT_H is maximum level ("high") of error correction: up to 30% of
# lost data bytes can be recovered.
QR_ECC_LEVEL = qrcode.constants.ERROR_CORRECT_H
QR_DATA_SIZE_BYTES = QR_SIZE_MAX_BYTES - Header.HEADER_SIZE_BYTES
QR_BOX_SIZE = 10
QR_BORDER = 5
MARGIN = QR_BOX_SIZE * QR_BORDER

def qr_image(data):
    qr = qrcode.QRCode(
        # int in range [1,40] to determine size, set to None and use fit= to
        # determine automatically.
        version=None,
        error_correction=QR_ECC_LEVEL,
        box_size=QR_BOX_SIZE,
        border=QR_BORDER
    )
    qrdata = qrcode.util.QRData(data,
                                # Don't try to guess data encoding.
                                mode=qrcode.util.MODE_8BIT_BYTE,
                                # Never try to encode data.
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
    w = max(img.size[0], 500)
    h = 320
    capt = Image.new('RGB', (w, h), 'white')
    d = ImageDraw.Draw(capt)
    title_font = ImageFont.truetype('fonts/DejaVuSans.ttf', 48)
    line_y = 310
    d.line(((MARGIN, line_y), (w - MARGIN, line_y)), 'gray')
    d.text((w/2, 70), title, fill='black', font=title_font, anchor='md',
           align='center')
    if subtitle:
        body_font = ImageFont.truetype('fonts/DejaVuSans.ttf', 24)
        d.text((w/2, 300), subtitle, fill='black', font=body_font, anchor='md',
               align='center')

    return merge_img_y(capt, img)

def qr_image_with_caption(data, caption, subtitle=None):
    img = qr_image(data)
    return add_caption(img, caption, subtitle)


class QREncoder(FileSegmentEncoder):

    def __init__(self, out_dir, secret_name):
        super().__init__(out_dir)
        self.secret_name = secret_name

    def encode(self, secret_data_segments, m, n):
        secret_data_segments = byte_seqs.resize_seqs(QR_DATA_SIZE_BYTES,
                                                     secret_data_segments)
        super().encode(secret_data_segments, m, n)

    def post_process(self, share_id, header, part_number, path):
        with path.open('rb') as f:
            data = f.read()

        img = qr_image(data)

        subtitle = f"Share {share_id} - " \
            f"Part {part_number}/{self.n_parts}\n" \
            f"Recover secret with {self.m} of {self.n} shares.\n" \
            f"Require all parts of each share.\n" \
            "Header Details:\n" \
            f"Version: {header.version}\n" \
            f"Segment: {header.segment_id}\n" \
            f"Authorized Set: {header.aset_id}\n" \
            f"Fragment: {header.fragment_id}"

        img = add_caption(img, self.secret_name, subtitle)
        img_path = path.with_suffix(".png")
        img.save(img_path)
        path.unlink()


def decode_qr_code(path):
    """
    Decode only QR code in image at path PATH, return byte array.
    """
    # Invoke zbarimg with args:
    # -Senable=0 -Sqrcode.enable=1
    #    Disable all decoders, then reenable only qrcode decoder
    #    If any other decoders are enabled, they occasionally detect spurious
    #    barcodes within the pattern of some qrcodes (about 1 / 100 times for
    #    ~50 data byte qrcodes).
    # --raw
    #    Don't prefix qrcode data with a url scheme qrcode:$DATA.
    # -Sbinary
    #    Don't decode qrcode data, return unmodified bytes instead.
    #
    # NOTE there must only be 1 QR code in the image! While zbarimg will decode
    # multiple QR codes, in binary mode it concatenates their payloads, so
    # there's no easy way to tell where one payload ends and the next begins
    proc = subprocess.run(
        ['zbarimg', '-Senable=0', '-Sqrcode.enable=1',
         '--raw', '-Sbinary', path],
        capture_output=True)
    if proc.returncode == 4:
        print(f"Warning: No QRCODE detected in {path}")
        return bytes()
    if proc.returncode < 0:
        # Then terminated by signal
        print(f"Warning: zbarimg terminated by signal {proc.returncode}")
        return bytes()
    if proc.returncode != 0:
        print(proc.stderr.decode())
        raise Exception(f"Failed to scan QRCODE in {path}")
    # Check stderr status message, looks like:
    # scanned 1 barcode symbols from 1 images in 0 seconds
    m = re.search(r'scanned (\d+) barcode.*from (\d+) image',
                  proc.stderr.decode())
    # Want 1 qrcode per (1) image
    if m.group(1) != '1' or m.group(2) != '1':
        print(proc.stderr.decode())
        raise Exception(f"Error: Got unexpected number of QRCODEs in {path}")
    return proc.stdout


class QRDecoder(FileDecoder):

    def read_file(self, path, *, seek=0):
        data = decode_qr_code(path)
        yield(data[seek:])






def test_codec(encoder, decoder, m, n, data_segments):
    data_segments = list(data_segments)
    encoder.encode(data_segments, m, n)

    result = list(decoder.decode())
    print(f"GOT RES {result}")

    # for aset in itertools.combinations(range(n), m):
    #     codec.use_authorized_set(aset)
    #     decoded = list(codec.decode())
    #     if (decoded != data_segments):
    #         print(f"Input:  {data_segments}")
    #         print(f"Result: {decoded}")
    #         raise Exception("Test failed, input != decode(encode(input))")

import random
def junk_data():
    return random.randbytes(2000)


d = Path("/tmp/triss-data-file-codec-test")
test_codec(QREncoder(d, "test secret"),
           QRDecoder([d / "share-1", d / "share-3" ], "png"),
           2, 4,
           [b'asdf', b'qwer']
           # {junk_data()}
           )
