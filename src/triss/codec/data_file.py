# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from collections import defaultdict
import math
import os
from pathlib import Path

from triss.codec import Writer, Appender, Reader, AppendingEncoder, Decoder, \
    TaggedInput
from triss.header import Header
from triss.util import eprint, print_exception

def header_name(header):
    def to_str(x):
        if isinstance(x, bytes):
            return x.decode(encoding='utf-8')
        return str(x)

    return ".".join(to_str(x) for x in header.to_key()) + ".dat"


class FileWriter(Writer):

    def __init__(self, out_dir):
        self.out_dir = Path(out_dir)

    def share_dir(self, share_id):
        return self.out_dir / f"share-{share_id}"

    def file_path(self, share_id, header):
        return self.share_dir(share_id) / header_name(header)

    def write(self, share_id, header, payload=None):
        dest = self.file_path(share_id, header)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            mode = 'r+b'
        else:
            mode = 'wb'
        with dest.open(mode=mode) as f:
            f.seek(0)
            f.write(header.to_bytes())
            if payload:
                f.write(payload)
            f.flush()
            os.fsync(f.fileno())

    def summary(self, encoder):
        self.n_parts_per_share = \
            encoder.n_asets_per_share * (encoder.n_segments +
                                         encoder.mac_slice_count)
        # Number of digits needed to print 1-based part number ordinals.
        self.part_num_width = int(math.log10(self.n_parts_per_share)) + 1
        self.part_numbers = defaultdict(int)

    def next_part_num_and_name(self, share_id):
        self.part_numbers[share_id] += 1
        n = self.part_numbers[share_id]
        # f-string: f"{3:05}" pads 3 with leading zeros to width 5: "00003"
        nf = f"{n:0{self.part_num_width}}"
        return (n,
                f"share-{share_id}_part-{nf}_of_"
                f"{self.n_parts_per_share}.dat")

    def post_process(self, header):
        share_id = header.metadata.share_id
        path = self.file_path(share_id, header)
        part_number, part_name = self.next_part_num_and_name(share_id)
        new_path = path.parent / part_name
        os.replace(path, new_path)
        header.metadata.path = new_path
        header.metadata.part_number = part_number


class FileAppender(FileWriter, Appender):

    def append(self, share_id, header, chunk):
        path = self.file_path(share_id, header)
        with path.open(mode='ab') as f:
            f.write(chunk)
            f.flush()
            os.fsync(f.fileno())


class FileReader(Reader):

    CHUNK_SIZE = 4096 * 16

    def __init__(self, in_dirs, *, file_extension="dat"):
        self.in_dirs = list(in_dirs)
        self.file_extension = file_extension

    def read_file(self, path, *, seek=0):
        with path.open("rb") as f:
            f.seek(seek)
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    return
                yield chunk

    def find_files(self):
        suffix = "." + self.file_extension
        for d in self.in_dirs:
            for path in Path(d).iterdir():
                if path.suffix == suffix:
                    yield path

    def locate_inputs(self):
        for f in self.find_files():
            try:
                header, _ = Header.parse(self.read_file(f))
                yield TaggedInput(header, f)
            except StopIteration:
                eprint(f"{type(self).__name__}: Unable to parse header in {f}:"
                       " file is empty, skipping it.")
            except Exception as e:
                eprint(f"{type(self).__name__}: Unable to parse header in {f},"
                       " skipping it. Parsing failed with:")
                print_exception(e)

    def payload_stream(self, tagged_input):
        return self.read_file(tagged_input.handle,
                              seek=tagged_input.header.size_bytes())


def encoder(out_dir, **opts):
    return AppendingEncoder(FileAppender(out_dir), **opts)


def decoder(in_dirs, *, file_extension="dat", **opts):
    reader = FileReader(in_dirs, file_extension=file_extension)
    return Decoder(reader, **opts)
