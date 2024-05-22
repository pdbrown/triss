import itertools
from collections import defaultdict, namedtuple

from triss import byte_seqs
from triss import crypto
from triss.util import ErrorMessage, eprint

class Header:
    VERSION = 1
    FIELDS = [['version', 2],
              ['flags', 2],
              ['segment_id', 4],
              ['aset_id', 4],
              ['fragment_id', 2]]
    # Field bytes + 2 for checksum
    HEADER_SIZE_BYTES = sum(n for (_, n) in FIELDS) + 2

    FLAG_LAST_FRAGMENT    = 0x0001
    FLAG_LAST_SEGMENT     = 0x0002

    def __init__(self, info):
        """Construct Header given INFO dictionary.

        INFO holds all header data, and is keyed by strings in self.FIELDS
        array.
        """
        if not 'version' in info:
            raise ValueError("Header info must contain 'version'")
        self.info = info
        for (f, l) in self.FIELDS:
            # Initialize to zero if undefined
            self.info[f] = self.info.get(f) or 0
            # Assert values in range
            self.get_bytes(f, l)

    def set_flag(self, flag):
        self.info['flags'] |= flag

    def get_bytes(self, k, l):
        """Return value of field K as byte array of length L."""
        v = self.info[k]
        return v.to_bytes(length=l, byteorder='big', signed=False)

    def test_flag(self, flag):
        """Return True if FLAG is set."""
        return bool(self.info['flags'] & flag)

    @property
    def version(self):
        return self.info['version']

    @property
    def segment_id(self):
        return self.info['segment_id']

    @property
    def aset_id(self):
        return self.info['aset_id']

    @property
    def fragment_id(self):
        return self.info['fragment_id']

    def to_bytes(self):
        """Return header as byte array."""
        data = bytes(itertools.chain.from_iterable(
            [self.get_bytes(f, l) for (f, l) in self.FIELDS]))
        return data + crypto.fletchers_checksum_16(data)

    @classmethod
    def create(cls, **info):
        """Construct Header from INFO at current Header.VERSION."""
        info['version'] = Header.VERSION
        return cls(info)

    @classmethod
    def parse(cls, data):
        """Parse byte array DATA and return instance of Header."""
        if len(data) < cls.HEADER_SIZE_BYTES:
            raise ValueError(f"Can't parse header, got {len(data)} bytes but "
                             f"needed {cls.HEADER_SIZE_BYTES} bytes.")
        data = data[0:cls.HEADER_SIZE_BYTES]
        checksum = bytes(data[-2:])  # last 2 bytes are checksum
        payload = bytes(data[0:-2])  # first n-2 bytes are payload
        if crypto.fletchers_checksum_16(payload) != checksum:
            raise ValueError("Refusing to parse header with bad checksum.")
        info = {}
        k = 0
        for (f, l) in cls.FIELDS:
            info[f] = int.from_bytes(payload[k:k+l], byteorder='big', signed=False)
            k += l

        if info['version'] != cls.VERSION:
            raise ValueError(f"Incompatible header version, got {info['version']}' "
                             f"but expected {cls.VERSION}")
        return cls.create(**info)


class Encoder:
    # Implementor's Interface
    def configure(self, m, n):
        m = m or n
        if m < 2 or n < 2:
            raise ErrorMessage("Must split into at least 2 shares.")
        if m > n:
            raise ErrorMessage("M cannot be larger than N for M-of-N split: "
                             f"got M={m} of N={n}")
        self.m = m
        self.n = n

    def encode_segments(self, secret_data_segments, m, n, authorized_sets):
        raise NotImplementedError()

    def summary(self, n_segments):
        self.n_segments = n_segments
        self.n_asets = crypto.num_asets(self.m, self.n)
        self.n_fragments = crypto.num_fragments_per_share(self.m, self.n)
        self.n_parts = self.n_segments * self.n_fragments

    def finalize(self, share_id, header):
        pass

    # Entrypoint
    def encode(self, secret_data_segments, m, n):
        self.configure(m, n)

        authorized_sets = crypto.m_of_n_access_structure(m, n)

        n_segments = self.encode_segments(
            secret_data_segments, m, n, authorized_sets)

        self.summary(n_segments)

        for segment_id in range(n_segments):
            for aset in authorized_sets:
                for fragment_id, share_id in enumerate(aset['share_ids']):
                    header = Header.create(segment_id=segment_id,
                                           aset_id=aset['aset_id'],
                                           fragment_id=fragment_id)
                    self.finalize(share_id, header)


class MappingEncoder(Encoder):

    def write(self, share_id, header, fragment):
        raise NotImplementedError()

    def encode_segments(self, secret_data_segments, m, n, authorized_sets):
        n_segments = 0
        for segment_id, secret_segment in enumerate(secret_data_segments):
            n_segments += 1
            # eprint(f"Segment: {segment_id}")
            for aset in authorized_sets:
                # eprint(f"  Aset: {aset}")
                for fragment_id, (share_id, fragment) in enumerate(
                        zip(aset['share_ids'],
                            crypto.split_secret(secret_segment, m))):
                    aset_id = aset['aset_id']
                    header = Header.create(segment_id=segment_id,
                                           aset_id=aset_id,
                                           fragment_id=fragment_id)
                    if fragment_id == m - 1:
                        header.set_flag(Header.FLAG_LAST_FRAGMENT)
                    self.write(share_id, header, fragment)
        return n_segments


class AppendingEncoder(Encoder):

    def __init__(self, mapping_encoder):
        self.mapping_encoder = mapping_encoder

    def configure(self, m, n):
        super().configure(m, n)
        self.mapping_encoder.configure(m, n)

    def append(self, share_id, aset_id, fragment_id, fragment):
        raise NotImplementedError()

    def encode_segments(self, secret_data_segments, m, n, authorized_sets):
        secret_data_segments = iter(secret_data_segments)
        try:
            first_segment = next(secret_data_segments)
        except StopIteration:
            # No segments available
            return 0

        self.mapping_encoder.encode_segments(
            [first_segment], m, n, authorized_sets)

        for secret_segment in secret_data_segments:
            for aset in authorized_sets:
                for fragment_id, (share_id, fragment) in enumerate(
                        zip(aset['share_ids'],
                            crypto.split_secret(secret_segment, m))):
                    self.append(share_id, aset['aset_id'], fragment_id, fragment)
        # All data is appended onto 1 segment
        return 1

    def summary(self, n_segments):
        self.mapping_encoder.summary(n_segments)

    def finalize(self, share_id, header):
        self.mapping_encoder.finalize(share_id, header)


class Decoder:
    # Helpers
    def name(self):
        return type(self).__name__

    def eprint(self, *args):
        eprint(f"{self.name()}:", *args)

    def throw(self, *args):
        raise ErrorMessage(" ".join([self.name(), *args]))

    # Interface
    def segments(self):
        raise NotImplementedError()

    def authorized_set(self, segment):
        raise NotImplementedError()

    def fragments(self, authorized_set):
        return [authorized_set]

    # Entrypoint
    def decode(self):
        for segment in self.segments():
            authorized_set = self.authorized_set(segment)
            for chunk_fragments in self.fragments(authorized_set):
                yield crypto.combine_fragments(chunk_fragments)


TaggedFragment = namedtuple("TaggedFragment", ["header", "handle"])

class TaggedDecoder(Decoder):

    def __init__(self, *, fragment_read_size=4096):
        self.fragment_read_size = fragment_read_size
        self.by_segment = defaultdict(list)
        self.m = None

    def fragment_streams(self):
        """Return iterator over (handle, fragment_stream) pairs."""
        raise NotImplementedError()

    def fragment_data_stream(self, handle):
        """Return iterator over fragment data chunks."""
        raise NotImplementedError()

    def print_discovered_fragments(self):
        if self.by_segment:
            self.eprint("Share fragments discovered:")
            for segment_id in sorted(self.by_segment.keys()):
                for tagged_frag in self.by_segment[segment_id]:
                    h = tagged_frag.header
                    self.eprint(f"segment_id={h.segment_id}, "
                                f"aset_id={h.aset_id}, "
                                f"fragment_id={h.fragment_id}: "
                                f"{tagged_frag.handle}")
        else:
            self.eprint("No share fragments discovered.")

    def segments(self):
        """Yield lists of TaggedFragments, one list per segment."""
        for handle, frag_stream in self.fragment_streams():
            try:
                chunk, frag_stream = byte_seqs.take_and_drop(
                    Header.HEADER_SIZE_BYTES, frag_stream)
            except StopIteration:
                self.eprint("Warning: No data in file, can't parse header: "
                            f"{handle}. Skipping.")
                continue
            try:
                header = Header.parse(chunk)
            except ValueError as e:
                self.eprint(e)
                self.eprint(f"Warning: Failed to parse header: {handle}. "
                            "Skipping.")
                continue

            # eprint(f"parsed header:", header.segment_id, header.aset_id, header.fragment_id)
            self.by_segment[header.segment_id].append(
                TaggedFragment(header, handle))

            if (header.test_flag(Header.FLAG_LAST_FRAGMENT)):
                m = header.fragment_id + 1
                if self.m is None:
                    self.m = m
                elif m != self.m:
                    self.print_discovered_fragments()
                    self.throw("Error: Inconsistent fragment count: "
                               f"old={self.m}, new={m}")

        if self.m is None:
            self.print_discovered_fragments()
            if not self.by_segment:
                msg = "Warning: No input found."
            else:
                msg = "Error: Unable to find complete set of fragments " \
                    "because no fragment has the Header.FLAG_LAST_FRAGMENT " \
                    "header flag set: Unable to determine the required " \
                    "number of fragments."
            self.throw(msg)

        segment_id = 0
        n_segments = len(self.by_segment)
        for segment_id in range(n_segments):
            segment = self.by_segment.get(segment_id)
            if not segment:
                self.print_discovered_fragments()
                self.throw(f"No segment for segment_id={segment_id}. "
                           f"Expected {len(self.by_segment)} segments.")
            if segment_id + 1 == n_segments:
                for frag in segment:
                    if not frag.header.test_flag(Header.FLAG_LAST_SEGMENT):
                        self.eprint(
                            "Warning: last segment (segment_id="
                            f"{segment_id}) didn't have FLAG_LAST_SEGMENT "
                            "set. May be missing trailing data.")
            yield segment

    def validate_aset(self, aset):
        for i in range(self.m):
            if not aset.get(i):
                self.eprint(f"Warning: found aset of correct size {self.m}, "
                            f"but it is missing fragment_id={i}")
                return False
        return True

    def authorized_set(self, segment):
        """Return list of handles to fragments of an authorized set."""
        asets = defaultdict(dict)
        for tagged_frag in segment:
            aset = asets[tagged_frag.header.aset_id]
            aset[tagged_frag.header.fragment_id] = tagged_frag
            if len(aset) == self.m and self.validate_aset(aset):
                return [tf.handle for tf in aset.values()]
        self.throw("Warning: unable to find complete authorized set of "
                   f"size {self.m}")

    def fragments(self, authorized_set):
        frag_streams = [byte_seqs.resize_seqs(self.fragment_read_size,
                                              self.fragment_data_stream(h))
                        for h
                        in authorized_set]
        while True:
            chunks = []
            for stream in frag_streams:
                try:
                    chunks.append(next(stream))
                except StopIteration:
                    return
            yield chunks
