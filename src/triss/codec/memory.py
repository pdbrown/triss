# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from collections import defaultdict

from triss.codec import Header, MappingEncoder, Decoder


def header_tuple(header):
    try:
        segment_id = header.segment_id
    except AttributeError:
        segment_id = -1
    return (header.tag, header.aset_id, header.fragment_id, segment_id)

class MemoryCodec(MappingEncoder, Decoder):

    def __init__(self):
        Decoder.__init__(self)
        self.parts = {}
        self.shares = defaultdict(list)
        self.decoder_share_ids = None

    # Encoder impl
    def write(self, share_id, header, fragment):
        data = header.to_bytes() + fragment
        k = header_tuple(header)
        self.parts[k] = data
        self.shares[share_id].append(k)

    def write_macs(self, share_id, header, mac_data_stream):
        self.write(share_id, header, b''.join(mac_data_stream))

    def patch_header(self, share_id, header_key, n_segments):
        k = header_tuple(header_key)
        data = self.parts[k]
        header, _ = Header.parse([data])
        header.segment_count = n_segments
        self.parts[k] = header.to_bytes() + data[header.size_bytes():]
        return header

    # Decoder impl
    def use_authorized_set(self, share_ids):
        self.decoder_share_ids = share_ids

    def input_streams(self):
        if self.decoder_share_ids is None:
            raise Exception("Call use_authorized_set first");
        for share_id in self.decoder_share_ids:
            for k in self.shares[share_id]:
                data = self.parts[k]
                yield((k, [data]))

    def payload_stream(self, tagged_input):
        header, k = tagged_input
        data = self.parts[k]
        return [data[header.size_bytes():]]
