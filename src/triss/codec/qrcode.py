# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import mimetypes
from pathlib import Path
import re
import subprocess

try:
    from PIL import Image, ImageDraw, ImageFont
    HAVE_PIL = True
except ModuleNotFoundError:
    HAVE_PIL = False

from triss import byte_streams
from triss.codec import Encoder, Decoder
from triss.codec.data_file import FileWriter, FileReader
from triss.header import FragmentHeader, MacHeader
from triss.util import eprint

mimetypes.init()

# QR_SIZE_MAX_BYTES is size of largest QR code with highest error correction
# enabled: Version 40, ECC level "High"
# See also https://www.qrcode.com/en/about/version.html
QR_SIZE_MAX_BYTES = 1273
QR_DATA_SIZE_BYTES = QR_SIZE_MAX_BYTES - FragmentHeader.size_bytes()
QR_MAC_DATA_SIZE_BYTES = QR_SIZE_MAX_BYTES - MacHeader.size_bytes()
QR_BOX_SIZE = 8
QR_BORDER = 6
MARGIN = QR_BOX_SIZE * QR_BORDER

TRY_FONTS = ["Helvetica.ttf", "DejaVuSans.ttf", "Arial.ttf"]


def eprint_stdout_stderr(proc):
    if proc.stdout:
        eprint(proc.stdout.decode('utf-8').strip())
    eprint_stderr(proc)


def eprint_stderr(proc):
    if proc.stderr:
        eprint(proc.stderr.decode('utf-8').strip())


def ensure_pil():
    if not HAVE_PIL:
        raise RuntimeError(
            "Error: QRCODE output format requires the Python Image Library "
            "(PIL) as provided by the pillow dist package, but it is not "
            "available.\n"
            "Try reinstalling triss:   pip install --upgrade triss\n"
            "or try installing pillow: pip install pillow")


def ensure_prog(cmdline, reason):
    prog = cmdline[0]
    try:
        proc = subprocess.run(cmdline, capture_output=True)
    except FileNotFoundError as e:
        raise RuntimeError(
            f"The external program {prog} is required {reason} but is not "
            "available on the PATH.") from e
    if proc.returncode != 0:
        eprint_stdout_stderr(proc)
        raise RuntimeError(
            f"The external program {prog} is required {reason}, but appears "
            f"to be broken. Try running: {' '.join(cmdline)}")


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
        raise RuntimeError(
            f"qrencode terminated by signal {proc.returncode} while writing "
            f"qrcode to {path}.")
    if proc.returncode != 0:
        eprint_stdout_stderr(proc)
        raise RuntimeError(
            f"qrencode failed with error writing to {path}.")


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


def pad_vertical(img):
    w, h = img.size
    if w <= h:
        return img
    out = Image.new('RGBA', (w, w + 1), 'white')
    out.paste(img)
    return out


def find_font(size):
    size = int(size)
    for font in TRY_FONTS:
        try:
            return ImageFont.truetype(font, size)
        except Exception:
            pass
    return None


def font_height(font, text, spacing=4):
    img = Image.new("RGBA", (1, 1))
    d = ImageDraw.Draw(img)
    (left, top, right, bottom) = d.multiline_textbbox(
        (0, 0), text, font=font, spacing=spacing)
    return bottom - top


def add_xy(pos, dxdy):
    x, y = pos
    dx, dy = dxdy
    return (x + dx, y + dy)


def add_caption(img, title, subtitle="", detail=""):
    # Resize images so text has constant size regardless of the qrcode IMG
    # size.
    spacing = 6
    qr_v40_modules = 177
    # width of version 40 qr code
    w = (qr_v40_modules + 2 * QR_BORDER) * QR_BOX_SIZE
    title_font = find_font(6 * QR_BOX_SIZE)
    subtitle_font = find_font(4 * QR_BOX_SIZE)
    detail_font = find_font(2.5 * QR_BOX_SIZE)
    title_h = font_height(title_font, title, spacing=spacing)
    subtitle_h = font_height(subtitle_font, subtitle, spacing=spacing)
    detail_h = font_height(detail_font, detail, spacing=spacing)
    y_margin = 6 * spacing
    h = MARGIN + title_h + subtitle_h + detail_h + 3 * y_margin
    capt = Image.new('RGBA', (w, h), 'white')
    d = ImageDraw.Draw(capt)
    cursor = (MARGIN, MARGIN)  # top-left corner of layout
    d.text(cursor, title, fill='black', font=title_font, spacing=spacing)
    cursor = add_xy(cursor, (0, title_h + y_margin))
    if subtitle:
        d.text(cursor, subtitle, fill='black', font=subtitle_font,
               spacing=spacing)
        cursor = add_xy(cursor, (0, subtitle_h + y_margin))
    if detail:
        d.text(cursor, detail, fill='black', font=detail_font, spacing=spacing)
    line_y = h - 1  # bottom of caption image
    d.line(((MARGIN, line_y), (w - MARGIN, line_y)), 'gray')

    captioned = merge_img_y(capt, img)
    # Add enough vertical padding to make image square so it prints in portrait
    # orientation by default.
    return pad_vertical(captioned)


def qr_encode(data, path, *, title="", subtitle="", detail=""):
    do_qrencode(data, path)
    img = load_image(path)
    if title:
        img = add_caption(img, title, subtitle, detail)
    img.save(path)
    return img


class QRWriter(FileWriter):

    def __init__(self, out_dir, secret_name):
        super().__init__(out_dir)
        self.secret_name = secret_name
        ensure_pil()
        ensure_prog(['qrencode', '--version'], "to encode QRCODEs")

    def summary(self, encoder):
        super().summary(encoder)
        self.m = encoder.m
        self.n = encoder.n

    def fragment_caption(self, header):
        subtitle = (f"Share {header.metadata.share_id} - "
                    f"Part {header.metadata.part_number}/"
                    f"{self.n_parts_per_share}\n"
                    f"Recover secret with {self.m} of {self.n} shares.\n"
                    f"Require all parts of each share.")
        detail = (
            "==== Part Details ====\n"
            f"{type(header).__name__} version: {header.version}\n"
            f"Authorized Set aset_id={header.aset_id}\n"
            f"Segment: {header.segment_id + 1}/{header.segment_count}\n"
            f"Fragment: {header.fragment_id + 1}/{header.fragment_count}")
        return (subtitle, detail)

    def mac_caption(self, header):
        subtitle = (f"Share {header.metadata.share_id} - "
                    f"Part {header.metadata.part_number}/"
                    f"{self.n_parts_per_share}\n"
                    f"Recover secret with {self.m} of {self.n} shares.\n"
                    f"Require all parts of each share.")
        detail = ("==== Part Details ====\n"
                  f"{type(header).__name__} version: {header.version}\n"
                  f"MACs for Authorized Set aset_id={header.aset_id}\n"
                  f"MAC key for fragment_id={header.fragment_id}\n"
                  f"MAC Slice: {header.slice_id + 1}/{header.slice_count}\n"
                  f"MAC Algorithm: {header.algorithm}")
        return (subtitle, detail)

    def post_process(self, header):
        super().post_process(header)
        if isinstance(header, FragmentHeader):
            subtitle, detail = self.fragment_caption(header)
        elif isinstance(header, MacHeader):
            subtitle, detail = self.mac_caption(header)
        else:
            raise RuntimeError(f"Invalid Header type: {type(header).__name__}")
        path = header.metadata.path
        with path.open('rb') as f:
            data = f.read()
        img_path = path.with_suffix(".png")
        qr_encode(data, img_path, title=self.secret_name,
                  subtitle=subtitle,
                  detail=detail)
        path.unlink()


class QREncoder(Encoder):

    def __init__(self, out_dir, secret_name, **opts):
        opts['mac_slice_size_bytes'] = QR_MAC_DATA_SIZE_BYTES
        super().__init__(QRWriter(out_dir, secret_name), **opts)

    def encode(self, secret_data_segments, m, n):
        secret_data_segments = byte_streams.resize_seqs(
            QR_DATA_SIZE_BYTES, secret_data_segments)
        super().encode(secret_data_segments, m, n)


def qr_decode(path):
    """
    Decode only QR code in image at path PATH, return byte array.
    """
    # Invoke zbarimg with args:
    # -Senable=0 -Sqrcode.enable=1
    #    Disable all decoders, then reenable only qrcode decoder
    #    If any other decoders are enabled, they occasionally detect spurious
    #    barcodes within the pattern of some qrcodes (about 1 / 100 times for
    #    random ~50 data byte qrcodes).
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
        eprint(f"No QRCODE detected in {path}.")
        return bytes()
    if proc.returncode < 0:
        # Then terminated by signal
        eprint(f"zbarimg terminated by signal {proc.returncode} while "
               f"attempting to read QRCODE in {path}.")
        return bytes()
    imagemagick_error = proc.returncode == 2
    bad_file_format = (proc.returncode == 1 and
                       re.search(r'no decode delegate', proc.stderr.decode()))
    if imagemagick_error or bad_file_format:
        eprint(f"Unable to read file as QRCODE image: {path}.")
        return bytes()
    if proc.returncode != 0:
        eprint_stderr(proc)
        raise RuntimeError(f"Failed to scan QRCODE in {path}.")
    # Check stderr status message, looks like:
    # scanned 1 barcode symbols from 1 images in 0 seconds
    m = re.search(r'scanned (\d+) barcode.*from (\d+) image',
                  proc.stderr.decode())
    # Want 1 qrcode per (1) image
    if m.group(1) != '1' or m.group(2) != '1':
        eprint_stderr(proc)
        eprint(f"Got unexpected number of QRCODEs in {path}.")
        return bytes()
    return proc.stdout


class QRReader(FileReader):

    def __init__(self, in_dirs):
        super().__init__(in_dirs)
        ensure_prog(['zbarimg', '--version'], "to decode QRCODEs")

    def read_file(self, path, *, seek=0):
        data = qr_decode(path)
        yield data[seek:]

    def find_files(self):
        for d in self.in_dirs:
            for path in Path(d).iterdir():
                mime_type = mimetypes.types_map.get(path.suffix.lower())
                if mime_type and re.split('/', mime_type)[0] == 'image':
                    yield path


def encoder(out_dir, secret_name, **opts):
    return QREncoder(out_dir, secret_name, **opts)


def decoder(in_dirs, **opts):
    return Decoder(QRReader(in_dirs), name="QRDecoder", **opts)
