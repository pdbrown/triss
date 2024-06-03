# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from collections import defaultdict

from triss.codec import MappingEncoder, Decoder

class MemoryCodec(MappingEncoder, Decoder):

    def __init__(self):
        Decoder.__init__(self)
        self.parts = defaultdict(list)
        self.decoder_share_ids = None

    # Encoder impl
    def write(self, share_id, header, fragment):
        data = header.to_bytes() + fragment
        self.parts[share_id].append((header, data))

    def write_macs(self, share_id, header, mac_data_stream):
        self.write(share_id, header, b''.join(mac_data_stream))

    def finalize(self, share_id, header):
        new_part = None
        for i, (h, data) in enumerate(self.parts[share_id]):
            if (h.aset_id == header.aset_id and
                h.segment_id == header.segment_id and
                h.fragment_id == header.fragment_id):
                hbs = header.to_bytes()
                new_part = (h, hbs + data[len(hbs):])
                break
        if new_part:
            self.parts[share_id][i] = new_part

    # Decoder impl
    def use_authorized_set(self, share_ids):
        self.decoder_share_ids = share_ids

    def input_streams(self):
        if self.decoder_share_ids is None:
            raise Exception("Call use_authorized_set first");
        for share_id in self.decoder_share_ids:
            for part_id, (header, data) in enumerate(self.parts[share_id]):
                yield((share_id, part_id), [data])

    def payload_stream(self, tagged_input):
        header, handle = tagged_input
        share_id, part_id = handle
        data = self.parts[share_id][part_id][1]
        return [data[header.size_bytes():]]
