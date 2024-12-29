# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from datetime import datetime
import importlib.metadata
import mimetypes
from pathlib import Path
import platform
import re
import subprocess
from subprocess import PIPE, Popen, TimeoutExpired
import sys

try:
    from PIL import Image, ImageDraw
except ModuleNotFoundError:
    pass

from triss import byte_streams, image
from triss.codec import Reader, Encoder, Decoder, TaggedInput
from triss.codec.data_file import FileWriter
from triss.header import FragmentHeader, MacHeader, \
    Header, InvalidHeaderError, HeaderParseError
from triss.util import eprint, print_exception

mimetypes.init()

# QR_SIZE_MAX_BYTES is size of largest QR code to generate. QR codes should
# hold as much data as feasible, but also be easy to scan. Their elements
# should be large enough for zbarimg and zbarcam to decode reliably. Tried
# Version 40 with ECC level "High" first, but zbarimg can't scan photos of
# those at all. (It can scan the original PNG images, but the whole point is to
# print them out and scan images of the printouts). Zbarcam can scan Version 40
# at full letter page size, but only after a few tries. To accommodate a wider
# range of camera and lighting conditions, settle on a smaller QR code, version
# 30, with a lower error correction level, medium, level 2 of 4. Damaged QR
# codes are less of a concern in this application, and version 30 on medium can
# hold about the same payload as version 40 on high correction, but the QR
# modules are larger and easier to scan. Note I could still not get zbarimg to
# work with photos these, but zbarcam had an easier time picking them up.
# See also https://www.qrcode.com/en/about/version.html
QR_SIZE_MAX_BYTES = 1370
QR_ECC_LEVEL = "M"
# Number of modules along each dimension of QR code at the maximum size:
# version 30
QR_NUM_MODULES = 137
QR_DATA_SIZE_BYTES = QR_SIZE_MAX_BYTES - FragmentHeader.size_bytes()
QR_MAC_DATA_SIZE_BYTES = QR_SIZE_MAX_BYTES - MacHeader.size_bytes()
# QR_MODULE_SIZE: A "module" is a single little square of the QR code,
# QR_MODULE_SIZE is its side length in pixels. This value also determines the
# resolution of the final output image (higher value => higher quality + larger
# image size).
QR_MODULE_SIZE = 8
# QR_BORDER: Empty margin around QR code in units of modules (i.e. QR code
# cells of side length QR_MODULE_SIZE). For a QR code to scan well, there needs
# to be pleny of whitespace around it, so be generous with this.
QR_BORDER = 20
MARGIN = QR_MODULE_SIZE * QR_BORDER


def eprint_stdout_stderr(proc):
    if proc.stdout:
        eprint(proc.stdout.decode('utf-8').strip())
    if proc.stderr:
        eprint(proc.stderr.decode('utf-8').strip())

def proc_stderr(proc):
    if proc.stderr:
        return proc.stderr.decode('utf-8').strip()
    else:
        return ""


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
    # --size 8
    #    Make each element 8x8 pixels large (default is 3x3).
    # --margin 6
    #    Use 6 px margin (default is 4).
    # --symversion auto
    #    Automatically choose qrcode data density depending on amount of DATA.
    #    Versions range between 1-40, version 40 is largest/densest, and holds
    #    1273 bytes of data in High error correction mode.
    proc = subprocess.run(
        ["qrencode", "-o", str(path), "--level", QR_ECC_LEVEL, "--8bit",
         "--size", str(QR_MODULE_SIZE), "--margin", str(QR_BORDER),
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


def add_caption(img, title, subtitle="", detail="", float_right=""):
    # Size images so text has constant size regardless of the qrcode size.
    spacing = 6
    # width of version qr code
    w = (QR_NUM_MODULES + 2 * QR_BORDER) * QR_MODULE_SIZE
    title_font = image.find_font(6 * QR_MODULE_SIZE)
    subtitle_font = image.find_font(4 * QR_MODULE_SIZE)
    detail_font = image.find_font(2.5 * QR_MODULE_SIZE)
    float_font = image.find_font(2.5 * QR_MODULE_SIZE)
    title_h = image.text_height(title, title_font, spacing=spacing)
    subtitle_h = image.text_height(subtitle, subtitle_font, spacing=spacing)
    detail_h = image.text_height(detail, detail_font, spacing=spacing)
    y_margin = 6 * spacing
    h = MARGIN + title_h + subtitle_h + detail_h + 3 * y_margin
    capt = Image.new('RGBA', (w, h), 'white')
    d = ImageDraw.Draw(capt)
    cursor = (MARGIN, MARGIN)  # top-left corner of layout
    d.text(cursor, title, fill='black', font=title_font, spacing=spacing)
    cursor = image.add_xy(cursor, (0, title_h + y_margin))
    if subtitle:
        d.text(cursor, subtitle, fill='black', font=subtitle_font,
               spacing=spacing)
        cursor = image.add_xy(cursor, (0, subtitle_h + y_margin))
    if detail:
        d.text(cursor, detail, fill='black', font=detail_font, spacing=spacing)
    line_y = h - 1  # bottom of caption image
    d.line(((MARGIN, line_y), (w - MARGIN, line_y)), 'gray')

    captioned = image.merge_y(capt, img)
    if float_right:
        float_img = image.text_img(float_right, float_font,
                                   spacing=spacing, padding=8)
        image.float_right(captioned, float_img, anchor=(MARGIN, MARGIN))

    # Add enough vertical padding to make image square so it prints in portrait
    # orientation by default.
    return image.pad_vertical(captioned)


def qr_encode(data, path, *, title="", subtitle="", detail="", float_right=""):
    do_qrencode(data, path)
    img = image.load(path)
    if title:
        img = add_caption(img, title, subtitle, detail, float_right)
    img.save(path)
    return img


def about_text():
    todays_date = datetime.today().strftime('%Y-%m-%d')
    uname = platform.uname()
    system_info = f"{uname.system} {uname.release}"
    python_version = "python version " + platform.python_version()
    triss_version = "triss version " + importlib.metadata.version('triss')
    qrencode_version = subprocess.check_output(
        ['qrencode', '--version']).decode().strip().split('\n')[0].strip()
    lines = [todays_date, system_info, python_version,
             triss_version, qrencode_version]
    return '\n'.join(line[0:30] for line in lines)


class QRWriter(FileWriter):

    def __init__(self, out_dir, secret_name):
        super().__init__(out_dir)
        self.secret_name = secret_name
        image.ensure_pil(what_for="QRCODE output requires")
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
                    f"Requires all {self.n_parts_per_share} parts of each share.")
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
        about = about_text()
        qr_encode(data, img_path, title=self.secret_name,
                  subtitle=subtitle,
                  detail=detail,
                  float_right=about)
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
    Decode QR codes in image at path PATH, return byte array.
    """
    # Invoke zbarimg with args:
    # -Senable=0 -Sqrcode.enable=1
    #    Disable all decoders, then reenable only qrcode decoder
    #    If any other decoders are enabled, they occasionally detect spurious
    #    barcodes within the pattern of some qrcodes (about 1 / 100 times for
    #    random ~50 data byte qrcodes).
    # --raw
    #    Don't prefix qrcode data with a url scheme qrcode:$DATA, or append a
    #    newline to the output.
    # -Sbinary
    #    Don't decode qrcode data, return unmodified bytes instead.
    proc = subprocess.run(
        ['zbarimg', '-Senable=0', '-Sqrcode.enable=1',
         '--raw', '-Sbinary', path],
        capture_output=True)
    if proc.returncode == 4:
        raise ValueError("No QRCODE detected.")
    if proc.returncode < 0:
        # Then terminated by signal
        raise RuntimeError(
            f"zbarimg terminated by signal {proc.returncode} while "
            f"attempting to read QRCODE.")
    imagemagick_error = proc.returncode == 2
    bad_file_format = (proc.returncode == 1 and
                       re.search(r'no decode delegate', proc.stderr.decode()))
    if imagemagick_error or bad_file_format:
        raise RuntimeError("Unable to read file as QRCODE image.")
    if proc.returncode != 0:
        raise RuntimeError("Failed to scan QRCODE: " + proc_stderr(proc))
    return proc.stdout


def parse_qr_data(stream):
    """
    Parse STREAM and yield tuples of (header, payload) or yield an error,

    a HeaderParseError exception object, if parsing fails.
    STREAM is an iterable of byte sequences.
    """
    while True:
        try:
            header, stream = Header.parse(stream)
        except StopIteration:
            return
        except HeaderParseError as hpe:
            header = None
            stream = hpe.byte_stream
            yield hpe

        if header is None:
            # No valid header at beginning of stream, throw away first byte and
            # try again.
            try:
                _garbage, stream = byte_streams.take_and_drop(1, stream)
                continue
            except StopIteration:
                return

        try:
            payload, stream = byte_streams.take_and_drop(
                header.payload_size, stream)
        except StopIteration as e:
            raise ValueError(
                f"Expected a QR data payload of {header.payload_size} bytes, "
                f"but got fewer for input with header {header}"
            ) from e
        yield (header, payload)


class QRInput:
    def __init__(self, path, data):
        self.path = path
        self.data = data

    def __repr__(self):
        return str(self.path)


class QRReaderBase(Reader):
    def payload_stream(self, tagged_input):
        return [tagged_input.handle.data]


class QRReader(QRReaderBase):

    def __init__(self, in_dirs):
        self.in_dirs = list(in_dirs)
        ensure_prog(['zbarimg', '--version'], "to decode QRCODEs from images")

    def find_files(self):
        for d in self.in_dirs:
            for path in Path(d).iterdir():
                mime_type = mimetypes.types_map.get(path.suffix.lower())
                if mime_type and re.split('/', mime_type)[0] == 'image':
                    yield path

    def locate_inputs(self):
        for f in self.find_files():
            try:
                data = qr_decode(f)
            except Exception as e:
                eprint(f"{type(self).__name__}: Unable to decoede QR data "
                       f"from {f}, skipping it. Failed with:")
                print_exception(e)
                continue

            error = None
            try:
                for result in parse_qr_data([data]):
                    if isinstance(result, Exception):
                        if not error:
                            error = result
                    else:
                        header, payload = result
                        handle = QRInput(f, payload)
                        yield TaggedInput(header, handle)
            except Exception as e:
                if not error:
                    error = e
            if error:
                eprint(f"{type(self).__name__}: Caught error reading QR "
                       f"data from {f}:")
                print_exception(error)


def qr_video_input():
    # Invoke zbarcam with args:
    # -Senable=0 -Sqrcode.enable=1
    #    Disable all decoders, then reenable only qrcode decoder
    #    If any other decoders are enabled, they occasionally detect spurious
    #    barcodes within the pattern of some qrcodes (about 1 / 100 times for
    #    random ~50 data byte qrcodes).
    # --raw
    #    Don't prefix qrcode data with a url scheme qrcode:$DATA. But NOTE
    #    unlike zbarimg, `zbarcam --raw ...` emits a newline after printing
    #    output, even when -Sbinary is set.
    # -Sbinary
    #    Don't decode qrcode data, return unmodified bytes instead.
    #
    # Note zbarcam also has an --xml flag, but -Sbinary is broken in xml output
    # mode. Otherwise, it would be convenient because it delmits scanned qrcode
    # data by xml tree node.
    #
    # Set bufsize=0 to make output unbuffered.
    with Popen(['zbarcam', '-Senable=0', '-Sqrcode.enable=1',
                '--raw', '-Sbinary'],
               stdout=PIPE, stderr=PIPE, bufsize=0) as proc:
        try:
            while True:
                status = proc.poll()
                if status is not None:
                    try:
                        out, err = proc.communicate(timeout=30)
                    except TimeoutExpired as e:
                        raise RuntimeError(
                            "Timeout waiting for last output from zbarcam "
                            "after it exited.") from e
                    if status == 0:
                        return
                    eprint(f"Non zero exit status from zbarcam: {status} "
                           f"with stdout: {out}\nstderr: {err}")
                    return
                # Yield 1 byte at a time to avoid blocking at the end of
                # scanning a qrcode, in order to give the user immediate
                # feedback after each scan.
                yield proc.stdout.read(1)
        except KeyboardInterrupt:
            proc.terminate()
            try:
                out, err = proc.communicate(timeout=30)
            except TimeoutExpired:
                eprint("Timeout waiting for zbarcam to terminate.")
                proc.kill()
            return


class QRScanner(QRReaderBase):

    def __init__(self):
        ensure_prog(['zbarcam', '--version'], "to scan QRCODEs from video")

    def locate_inputs(self):
        eprint("Scanning QR codes with default camera.")
        eprint("Close the scanner window or send a keyboard interrupt "
               "(Ctrl-C) to continue once you're done scanning.")
        try:
            for result in parse_qr_data(qr_video_input()):
                if isinstance(result, ExceptionGroup):
                    ihes = [e for e in result.exceptions
                            if isinstance(e, InvalidHeaderError)]
                    if ihes:
                        eprint(f"{type(self).__name__}: Unable to parse header of "
                               f"QR data in video stream, skipping it. "
                               "Parsing failed with:")
                    for e in ihes:
                        print_exception(e, prefix="  ")
                else:
                    header, payload = result
                    handle = QRInput("QRScanner camera input", payload)
                    eprint(f"Scanned QR code: {header}")
                    yield TaggedInput(header, handle)
        except Exception as e:
            eprint(f"{type(self).__name__}: Caught error reading QR "
                   f"data from default camera video stream:")
            print_exception(e)


class QRReaderScanner(QRReaderBase):
    def __init__(self, reader):
        self.reader = reader
        self.scanner = QRScanner()

    def locate_inputs(self):
        yield from self.reader.locate_inputs()
        yield from self.scanner.locate_inputs()


def encoder(out_dir, secret_name, **opts):
    return QREncoder(out_dir, secret_name, **opts)


def decoder(in_dirs, **opts):
    if in_dirs:
        reader = QRReader(in_dirs)
        if opts.get('scanner', False):
            del opts["scanner"]
            reader = QRReaderScanner(reader)
    elif opts.get('scanner', False):
        del opts["scanner"]
        reader = QRScanner()
    return Decoder(reader, **opts)
