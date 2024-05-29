# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import mimetypes
from pathlib import Path
import re
import subprocess

import qrcode
from PIL import Image, ImageDraw, ImageFont

from triss import byte_seqs
from triss.codec import FragmentHeader, TaggedDecoder
from triss.codec.data_file import FileSegmentEncoder, FileDecoder
from triss.util import ErrorMessage, eprint

mimetypes.init()

# From https://www.qrcode.com/en/about/version.html
# Set QR_SIZE_MAX_BYTES to be size of largest QR code with highest error
# correction enabled: Version 40, ECC level "High"
QR_SIZE_MAX_BYTES = 1273
QR_DATA_SIZE_BYTES = QR_SIZE_MAX_BYTES - FragmentHeader.size_bytes()
QR_BOX_SIZE = 10
QR_BORDER = 20
MARGIN = QR_BOX_SIZE * QR_BORDER

TRY_FONTS = ["Helvetica.ttf", "DejaVuSans.ttf", "Arial.ttf"]

def do_qrencode(data, path):
    # Invoke qrencode with args:
    # -o PATH
    #    Write png output to PATH
    # --level H
    #    Use 'H'igh error correction level (avaliable levels from lowest to
    #    highest: LMQH)
    # --8bit
    #    Use 8bit binary encoding, i.e. don't modify input in any way.
    # --size 10
    #    Make each element 5x5 pixels large (default is 3x3).
    # --margin 10
    #    Use 10 px margin (default is 4).
    # --symversion auto
    #    Automatically choose qrcode data density depending on amount of DATA.
    #    Versions range between 1-40, version 40 is largest/densest, and holds
    #    1273 bytes of data in High error correction mode.
    proc = subprocess.run(
        ["qrencode", "-o", str(path), "--level", "H", "--8bit",
         "--size", str(QR_BOX_SIZE), "--margin", str(QR_BORDER),
         "--symversion", "auto"],
        input=data,
        capture_output=True)

    if proc.returncode < 0:
        # Then terminated by signal
        eprint(f"Warning: qrencode terminated by signal {proc.returncode} "
               f"while writing qrcode to {path}.")
        return False
    if proc.returncode != 0:
        eprint(proc.stdout.decode())
        eprint(proc.stderr.decode())
        eprint(f"Warning: qrencode failed with error writing to {path}.")
        return False
    return True

def load_image(path):
    # Read image data into img, then close img_path keeping img in memory.
    with Image.open(path) as img:
        img.load()
    return img

def merge_img_y(im_top, im_bottom):
    w = max(im_top.size[0], im_bottom.size[0])
    h = im_top.size[1] + im_bottom.size[1]
    im = Image.new('RGBA', (w, h), 'white')
    im.paste(im_top)
    im.paste(im_bottom, (0, im_top.size[1]))
    return im

def find_font(size):
    for font in TRY_FONTS:
        try:
            return ImageFont.truetype(font, size)
        except Exception:
            pass
    return None

def add_caption(img, title, subtitle=None):
    w = max(img.size[0], 500)
    h = 320
    capt = Image.new('RGB', (w, h), 'white')
    d = ImageDraw.Draw(capt)
    title_font = find_font(48)
    line_y = 310
    d.line(((MARGIN, line_y), (w - MARGIN, line_y)), 'gray')
    d.text((w/2, 70), title, fill='black', font=title_font, anchor='md',
           align='center')
    if subtitle:
        body_font = find_font(24)
        d.text((w/2, 300), subtitle, fill='black', font=body_font, anchor='md',
               align='center')

    return merge_img_y(capt, img)

def qr_encode(data, path, *, title=None, subtitle=None):
    if not do_qrencode(data, path):
        return None
    img = load_image(path)
    if title:
        img = add_caption(img, title, subtitle)
    img.save(path)
    return img


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

        img_path = path.with_suffix(".png")
        subtitle = f"Share {share_id} - " \
            f"Part {part_number}/{self.n_parts}\n" \
            f"Recover secret with {self.m} of {self.n} shares.\n" \
            f"Require all parts of each share.\n" \
            "--- Header Details ---\n" \
            f"Version: {header.version}\n" \
            f"Segment: {header.segment_id + 1}/{header.segment_count}\n" \
            f"Authorized Set: {header.aset_id}\n" \
            f"Fragment: {header.fragment_id + 1}/{header.fragment_count}"

        qr_encode(data, img_path, title=self.secret_name, subtitle=subtitle)
        path.unlink()


def qr_decode(path):
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
        eprint(f"Warning: No QRCODE detected in {path}. Skipping it.")
        return bytes()
    if proc.returncode < 0:
        # Then terminated by signal
        eprint(f"Warning: zbarimg terminated by signal {proc.returncode} "
               f"while attempting to read QRCODE in {path}. Skipping it.")
        return bytes()
    imagemagick_error = proc.returncode == 2
    bad_file_format = proc.returncode == 1 and \
        re.search(r'no decode delegate', proc.stderr.decode())
    if imagemagick_error or bad_file_format:
        eprint(f"Warning: unable to read file as QRCODE image: {path}. "
               "Skipping it.")
        return bytes()
    if proc.returncode != 0:
        eprint(proc.stderr.decode())
        raise ErrorMessage(
            f"Error: Failed to scan QRCODE in {path}. Aborting.")
    # Check stderr status message, looks like:
    # scanned 1 barcode symbols from 1 images in 0 seconds
    m = re.search(r'scanned (\d+) barcode.*from (\d+) image',
                  proc.stderr.decode())
    # Want 1 qrcode per (1) image
    if m.group(1) != '1' or m.group(2) != '1':
        eprint(proc.stderr.decode())
        eprint(f"Warning: Got unexpected number of QRCODEs in {path}. " \
               "Skipping it.")
        return bytes()
    return proc.stdout


class QRDecoder(FileDecoder):

    def __init__(self, in_dirs, **opts):
        super().__init__(in_dirs, **opts)
        try:
            proc = subprocess.run(['zbarimg', '--version'],
                                  capture_output=True)
        except FileNotFoundError:
            raise ErrorMessage(
                "The external program zbarimg is required to decode QRCODEs "
                "but is not available on the PATH.")
        if proc.returncode != 0:
            eprint(proc.stderr.decode())
            raise ErrorMessage(
                "The external program zbarimg is required to decode QRCODEs "
                "appears to be broken. Try running: zbarimg --version")


    def read_file(self, path, *, seek=0):
        data = qr_decode(path)
        yield(data[seek:])

    def find_files(self):
        for d in self.in_dirs:
            for path in Path(d).iterdir():
                mime_type = mimetypes.types_map.get(path.suffix.lower())
                if mime_type and re.split('/', mime_type)[0] == 'image':
                    yield path
