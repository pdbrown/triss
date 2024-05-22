# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from collections import defaultdict
import itertools
import math
import os
from pathlib import Path

from triss.codec import Header, MappingEncoder, AppendingEncoder, TaggedDecoder
from triss.util import ErrorMessage, eprint

def set_last_segment(path):
    with path.open(mode='rb+') as f:
        header = Header.parse(f.read(Header.HEADER_SIZE_BYTES))
        header.set_flag(Header.FLAG_LAST_SEGMENT)
        f.seek(0)
        f.write(header.to_bytes())


class FileSegmentEncoder(MappingEncoder):

    def __init__(self, out_dir):
        self.out_dir = out_dir

    def file_path(self, share_id, header):
        name = f"{header.segment_id}.{header.aset_id}.{header.fragment_id}.dat"
        return Path(self.out_dir) / f"share-{share_id}" / name

    def write(self, share_id, header, fragment):
        dest = self.file_path(share_id, header)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open(mode='wb') as f:
            f.write(header.to_bytes())
            f.write(fragment)

    def summary(self, n_segments):
        super().summary(n_segments)
        if n_segments > 0:
            # Number of digits needed to print 1-based part number ordinals.
            self.part_num_width = int(math.log10(self.n_parts)) + 1
            self.part_numbers = defaultdict(int)

    def finalize(self, share_id, header):
        # eprint(f"finalize: seg {segment_id}, aset: {aset_id}, share: {share_id}, frag: {fragment_id}")
        last_segment = header.segment_id == self.n_segments - 1
        self.part_numbers[share_id] += 1
        part_number = self.part_numbers[share_id]

        old_path = self.file_path(share_id, header)
        # f-string: f"{3:05}" pads 3 with leading zeros to width 5: "00003"
        new_name = f"share-{share_id}_part-" \
                   f"{part_number:0{self.part_num_width}}" \
                   f"_of_{self.n_parts}.dat"
        new_path = old_path.parent / new_name
        os.replace(old_path, new_path)
        # eprint(f"rename: {old_path} -> {new_path}")
        if last_segment:
            set_last_segment(new_path)

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
            share_id, Header.create(segment_id=self.SEGMENT_ID,
                                    aset_id=aset_id,
                                    fragment_id=fragment_id))
        with path.open(mode='ab') as f:
            f.write(fragment)


class FileDecoder(TaggedDecoder):

    CHUNK_SIZE = 4096

    def __init__(self, in_dirs, *, file_extension="dat", **opts):
        super().__init__(**opts)
        self.in_dirs = in_dirs
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

    def fragment_streams(self):
        for f in self.find_files():
            yield (f, self.read_file(f))

    def fragment_data_stream(self, handle):
        return self.read_file(handle, seek=Header.HEADER_SIZE_BYTES)
