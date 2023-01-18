import itertools
from collections import defaultdict

from triss.codec import MappingEncoder, Decoder


class MemoryCodec(MappingEncoder, Decoder):

    def __init__(self):
        self.store = []
        self.store_segment = None
        self.current_segment_id = None
        self.m = 0
        self.n = 0
        self.decoder_share_ids = None

    # Encoder impl
    def write(self, share_id, header, fragment):
        if header.segment_id != self.current_segment_id:
            self.current_segment_id = header.segment_id
            self.store_segment = defaultdict(dict)
            self.store.append(self.store_segment)
        self.store_segment[share_id][header.aset_id] = fragment

    # Decoder impl
    def use_authorized_set(self, share_ids):
        self.decoder_share_ids = share_ids

    def analyze(self):
        return self.store

    def segments(self):
        if self.decoder_share_ids is None:
            raise Error("Call use_authorized_set first");
        for segment in self.store:
            frags = []
            for share_id in self.decoder_share_ids:
                for aset_id, fragment in segment[share_id].items():
                    frags.append((aset_id, fragment))
            yield frags

    def authorized_set(self, segment):
        frags = defaultdict(list)
        for (aset_id, fragment) in segment:
            aset_frags = frags[aset_id]
            aset_frags.append(fragment)
            if len(aset_frags) == self.m:
                return aset_frags
        return None


def test_codec(codec, m, n, data_segments):
    data_segments = list(data_segments)
    codec.encode(data_segments, m, n)

    for aset in itertools.combinations(range(n), m):
        codec.use_authorized_set(aset)
        decoded = list(codec.decode())
        print(f"Input:  {data_segments}")
        print(f"Result: {decoded}")

        if (decoded != data_segments):
            raise Exception("Test failed, input != decode(encode(input))")



test_codec(MemoryCodec(), 2, 4, [b'asdf', b'qwer'])
