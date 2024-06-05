# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from collections import defaultdict
import itertools
import math
import os
from pathlib import Path

from triss import codec
from triss.codec import FragmentHeader, MacHeader, \
    MappingEncoder, AppendingEncoder, Decoder
from triss.util import eprint

def set_segment_count(path, segment_count):
    with path.open(mode='rb+') as f:
        header = FragmentHeader.from_bytes(f.read(FragmentHeader.size_bytes()))
        header.segment_count = segment_count
        f.seek(0)
        f.write(header.to_bytes())


class FileSegmentEncoder(MappingEncoder):

    def __init__(self, out_dir):
        self.out_dir = Path(out_dir)

    def share_dir(self, share_id):
        return self.out_dir / f"share-{share_id}"

    def file_path(self, share_id, header):
        name = f"{header.segment_id}.{header.aset_id}.{header.fragment_id}.dat"
        return self.share_dir(share_id) / name

    def write(self, share_id, header, fragment):
        dest = self.file_path(share_id, header)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open(mode='wb') as f:
            f.write(header.to_bytes())
            f.write(fragment)

    def summary(self, n_segments):
        super().summary(n_segments)
        # Add one extra part per aset to hold macs
        n_frag_parts = self.n_segments * self.n_asets_per_share
        n_mac_parts = self.n_asets_per_share
        self.n_parts_per_share = n_frag_parts + n_mac_parts
        # Number of digits needed to print 1-based part number ordinals.
        self.part_num_width = int(math.log10(self.n_parts_per_share)) + 1
        self.part_numbers = defaultdict(int)

    def next_part_num_name(self, share_id):
        self.part_numbers[share_id] += 1
        n = self.part_numbers[share_id]
        # f-string: f"{3:05}" pads 3 with leading zeros to width 5: "00003"
        nf = f"{n:0{self.part_num_width}}"
        return (n, f"share-{share_id}_part-{nf}_of_"
                f"{self.n_parts_per_share}.dat")

    def write_macs(self, share_id, header, mac_data_stream):
        _, name = self.next_part_num_name(share_id)
        path = self.share_dir(share_id) / name
        with path.open(mode='wb') as f:
            f.write(header.to_bytes())
            for chunk in mac_data_stream:
                f.write(chunk)

    def finalize(self, share_id, header):
        path = self.file_path(share_id, header)
        set_segment_count(path, self.n_segments)
        part_number, part_name = self.next_part_num_name(share_id)
        new_path = path.parent / part_name
        os.replace(path, new_path)
        self.post_process(share_id, header, part_number, new_path)

    def post_process(self, share_id, header, part_number, path):
        pass



class FileEncoder(AppendingEncoder):

    SEGMENT_ID = 0

    def __init__(self, out_dir):
        super().__init__(FileSegmentEncoder(out_dir))
        self.out_dir = out_dir

    def append(self, share_id, aset_id, fragment_id, fragment):
        path = self.mapping_encoder.file_path(
            share_id,
            FragmentHeader(segment_id=self.SEGMENT_ID,
                           aset_id=aset_id,
                           fragment_id=fragment_id))
        with path.open(mode='ab') as f:
            f.write(fragment)


class FileDecoder(Decoder):

    CHUNK_SIZE = 4096 * 16

    def __init__(self, in_dirs, *, file_extension="dat", **opts):
        super().__init__(**opts)
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

    def input_streams(self):
        for f in self.find_files():
            yield (f, self.read_file(f))

    def payload_stream(self, tagged_input):
        return self.read_file(tagged_input.handle,
                              seek=tagged_input.header.size_bytes())
