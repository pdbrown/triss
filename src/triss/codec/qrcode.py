# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from collections import defaultdict
import math
import mimetypes
from pathlib import Path
import re
import subprocess

import qrcode
from PIL import Image, ImageDraw, ImageFont

from triss import byte_seqs, crypto
from triss.codec import FragmentHeader, MacHeader, TaggedDecoder
from triss.codec.data_file import FileSegmentEncoder, FileDecoder
from triss.util import ErrorMessage, eprint, div_up

mimetypes.init()

# From https://www.qrcode.com/en/about/version.html
# Set QR_SIZE_MAX_BYTES to be size of largest QR code with highest error
# correction enabled: Version 40, ECC level "High"
QR_SIZE_MAX_BYTES = 1273
QR_DATA_SIZE_BYTES = QR_SIZE_MAX_BYTES - FragmentHeader.size_bytes()
QR_MAC_DATA_SIZE_BYTES = QR_SIZE_MAX_BYTES - MacHeader.size_bytes()
QR_BOX_SIZE = 10
QR_BORDER = 10
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
        ensure_prog(['qrencode', '--version'], "to encode QRCODEs")

    def encode(self, secret_data_segments, m, n,
               mac_size_bits=crypto.DEFAULT_MAC_SIZE_BITS):
        secret_data_segments = byte_seqs.resize_seqs(QR_DATA_SIZE_BYTES,
                                                     secret_data_segments)
        super().encode(secret_data_segments, m, n, mac_size_bits=mac_size_bits)

    def summary(self, n_segments):
        super().summary(n_segments)
        # Reserve space for MACs: 1 per share + 1 key for the current share
        hmac_data_size_bytes = (self.n + 1) * self.mac_size_bits // 8
        self.hmac_part_count = div_up(hmac_data_size_bytes,
                                      QR_MAC_DATA_SIZE_BYTES)
        self.n_parts = self.n_fragments + self.hmac_part_count
        # Number of digits needed to print 1-based part number ordinals.
        self.part_num_width = int(math.log10(self.n_parts)) + 1
        self.part_numbers = defaultdict(int)

    def write_hmacs(self):
        for share_id in range(self.n):
            hmac_bs = byte_seqs.resize_seqs(QR_MAC_DATA_SIZE_BYTES,
                                            self.hmac_byte_stream(share_id))
            for part_id, hmac_chunk in enumerate(hmac_bs):
                part_num, name = self.next_part_num_name(share_id)
                path = (self.share_dir(share_id) / name).with_suffix(".png")
                header = MacHeader.create(
                    share_count=self.n,
                    part_id=part_id,
                    part_count=self.hmac_part_count,
                    size=self.macs[0].size,
                    algorithm=self.macs[0].algo)
                data = header.to_bytes() + hmac_chunk
                subtitle = f"Share {share_id} - " \
                    f"Part {part_num}/{self.n_parts}\n" \
                    f"Recover secret with {self.m} of {self.n} shares.\n" \
                    f"Require all parts of each share.\n" \
                    "--- Header Details ---\n" \
                    f"Version: {header.version}\n" \
                    f"HMAC Segment: {part_id + 1}/{self.hmac_part_count}\n" \
                    f"Algorithm: {header.algorithm}"
                qr_encode(data, path, title=self.secret_name, subtitle=subtitle)

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
        ensure_prog(['zbarimg', '--version'], "to decode QRCODEs")

    def read_file(self, path, *, seek=0):
        data = qr_decode(path)
        yield(data[seek:])

    def find_files(self):
        for d in self.in_dirs:
            for path in Path(d).iterdir():
                mime_type = mimetypes.types_map.get(path.suffix.lower())
                if mime_type and re.split('/', mime_type)[0] == 'image':
                    yield path


def ensure_prog(cmdline, reason):
    prog = cmdline[0]
    try:
        proc = subprocess.run(cmdline, capture_output=True)
    except FileNotFoundError:
        raise ErrorMessage(
            f"The external program {prog} is required {reason} but is not "
            "available on the PATH.")
    if proc.returncode != 0:
        eprint(proc.stderr.decode())
        raise ErrorMessage(
            f"The external program {prog} is required {reason}, but appears to "
            f"be broken. Try running: {' '.join(cmdline)}")
