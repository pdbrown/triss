# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from collections import defaultdict

from triss.codec import Codec, Writer, Reader, Encoder, Decoder
from triss.header import Header

class MemoryStore(Writer, Reader):
    """
    A MemoryStore implements in-memory secret splits for testing.
    """
    def __init__(self):
        self.parts = {}
        self.shares = defaultdict(list)
        self.decoder_share_ids = None

    # Writer impl
    def write(self, share_id, header, payload=None):
        k = header.to_key()
        try:
            h, p = self.parts[k]
            header = header or h
            payload = payload or p
        except KeyError:
            pass
        self.parts[k] = (header.to_bytes(), payload)
        share = self.shares[share_id]
        if k not in share:
            share.append(k)

    # Reader impl
    def select_authorized_set(self, share_ids):
        self.decoder_share_ids = share_ids

    def input_streams(self):
        if self.decoder_share_ids is None:
            raise Exception("Call select_authorized_set first")
        for share_id in self.decoder_share_ids:
            for k in self.shares[share_id]:
                data = self.parts[k]
                yield((k, data))

    def payload_stream(self, tagged_input):
        header, k = tagged_input
        (_, payload) = self.parts[k]
        return [payload]


def codec(**opts):
    store = MemoryStore()
    return Codec(Encoder(store, **opts), Decoder(store, **opts))
