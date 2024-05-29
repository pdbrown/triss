from enum import IntEnum
import itertools
from collections import defaultdict, namedtuple

from triss import byte_seqs
from triss import crypto
from triss.util import ErrorMessage, eprint

class Header:
    TAG = int.from_bytes(b'triss')

    @classmethod
    def fields(cls):
        return cls.FIELDS.keys()

    @classmethod
    def length(cls, k):
        return cls.FIELDS[k]

    @classmethod
    def parse_field(cls, k, data):
        return int.from_bytes(data, byteorder='big', signed=False)

    @classmethod
    def size_bytes(cls):
        # Length of all fields + 2 bytes for checksum.
        return sum(cls.length(k) for k in cls.fields()) + 2

    def __init__(self, info):
        """Construct Header given INFO dictionary.

        INFO holds all header data, and is keyed by strings in self.fields()
        array.
        """
        info['tag'] = self.TAG
        if not 'version' in info:
            raise ValueError("Header info must contain 'version'")
        self.info = info
        for k in self.fields():
            # Initialize to zero if undefined
            self.info[k] = self.info.get(k) or 0
            # Assert values in range. get_bytes throws an OverflowError if
            # value is to big to convert.
            self.get_bytes(k)

    def get_bytes(self, k):
        """Return value of field K as byte array."""
        v = self.info[k]
        l = self.length(k)
        return v.to_bytes(length=l, byteorder='big', signed=False)

    @property
    def version(self):
        return self.info['version']

    def to_bytes(self):
        """Return header as byte array."""
        data = bytes(itertools.chain.from_iterable(
            [self.get_bytes(f) for (f) in self.fields()]))
        return data + crypto.fletchers_checksum_16(data)

    @classmethod
    def create(cls, **info):
        """Construct Header from INFO at current Header.VERSION."""
        info['version'] = cls.VERSION
        return cls(info)

    @classmethod
    def parse(cls, data):
        """Parse byte array DATA and return instance of Header."""
        size = cls.size_bytes()
        if len(data) < size:
            raise ValueError(f"Can't parse header, got {len(data)} bytes but "
                             f"needed {size} bytes.")
        data = data[0:size]
        checksum = bytes(data[-2:])  # last 2 bytes are checksum
        payload = bytes(data[0:-2])  # first n-2 bytes are payload
        if crypto.fletchers_checksum_16(payload) != checksum:
            raise ValueError("Refusing to parse header with bad checksum.")
        info = {}
        i = 0
        for k in cls.fields():
            l = cls.length(k)
            info[k] = cls.parse_field(k, payload[i:i+l])
            i += l
        if info['tag'] != cls.TAG:
            raise ValueError("Header tag is not 'triss': is this a triss file?")
        if info['version'] != cls.VERSION:
            raise ValueError(f"Incompatible header version, got {info['version']}' "
                             f"but expected {cls.VERSION}")
        return cls.create(**info)

class FragmentHeader(Header):
    VERSION = 1
    FIELDS = {'tag': 5,
              'version': 1,
              'aset_id': 4,
              'segment_id': 4,
              'segment_count': 4,
              'fragment_id': 2,
              'fragment_count': 2}

    @property
    def aset_id(self):
        return self.info['aset_id']

    @property
    def segment_id(self):
        return self.info['segment_id']

    @property
    def segment_count(self):
        return self.info['segment_count']

    @segment_count.setter
    def segment_count(self, n):
        self.info['segment_count'] = n

    @property
    def fragment_id(self):
        return self.info['fragment_id']

    @property
    def fragment_count(self):
        return self.info['fragment_count']


class MacType(IntEnum):
    KEY = 1
    HMAC = 2

class MacHeader(Header):
    TAG = int.from_bytes(b'trissmac')
    VERSION = 1
    FIELDS = {'tag': 8,
              'version': 1,
              'type': 1,
              'share_id': 4,
              'size': 4,
              'algorithm': 14}

    @classmethod
    def parse_field(cls, k, data):
        if k == 'type':
            return MacType(super().parse_field(k, data))
        elif k == 'algorithm':
            return data.decode("utf-8")
        else:
            return super().parse_field(k, data)

    @property
    def type(self):
        return self.info['type']

    @property
    def share_id(self):
        return self.info['share_id']

    @property
    def size(self):
        return self.info['size']

    @property
    def algorithm(self):
        return self.info['algorithm']



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
                    header = FragmentHeader.create(aset_id=aset['aset_id'],
                                                   segment_id=segment_id,
                                                   segment_count=n_segments,
                                                   fragment_id=fragment_id,
                                                   fragment_count=m)
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
                    header = FragmentHeader.create(aset_id=aset['aset_id'],
                                                   segment_id=segment_id,
                                                   fragment_id=fragment_id,
                                                   fragment_count=m)
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
    def load(self):
        pass

    def segments(self):
        raise NotImplementedError()

    def authorized_set(self, segment):
        raise NotImplementedError()

    def fragments(self, authorized_set):
        return [authorized_set]

    # Entrypoint
    def decode(self):
        self.load()
        for segment in self.segments():
            authorized_set = self.authorized_set(segment)
            for chunk_fragments in self.fragments(authorized_set):
                yield crypto.combine_fragments(chunk_fragments)


TaggedFragment = namedtuple("TaggedFragment", ["header", "handle"])

class TaggedDecoder(Decoder):

    def __init__(self, *, fragment_read_size=4096):
        self.fragment_read_size = fragment_read_size
        self.by_segment = defaultdict(list)

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

    def ensure_segment_count(self, header):
        if header.segment_count == 0:
            self.throw(f"Error: Invalid segment_count=0 for: {handle}")
        if self.segment_count == 0:
            self.segment_count = header.segment_count
        elif self.segment_count != header.segment_count:
            self.throw(
                f"Error: Inconsistent segment_count. Expected "
                f"{self.segment_count} but got {header.segment_count} in "
                f"{handle}")

    def ensure_fragment_count(self, header):
        if header.fragment_count == 0:
            self.throw(f"Error: Invalid fragment_count=0 for: {handle}")
        if self.fragment_count == 0:
            self.fragment_count = header.fragment_count
        elif self.fragment_count != header.fragment_count:
            self.throw(
                f"Error: Inconsistent fragment_count. Expected "
                f"{self.fragment_count} but got {header.fragment_count} in "
                f"{handle}")

    def load(self):
        self.segment_count = 0
        self.fragment_count = 0
        for handle, frag_stream in self.fragment_streams():
            try:
                chunk, frag_stream = byte_seqs.take_and_drop(
                    FragmentHeader.size_bytes(), frag_stream)
            except StopIteration:
                self.eprint("Warning: No data in file, can't parse header: "
                            f"{handle}. Skipping.")
                continue
            try:
                header = FragmentHeader.parse(chunk)
            except ValueError as e:
                self.eprint(e)
                self.eprint(f"Warning: Failed to parse header: {handle}. "
                            "Skipping.")
                continue

            self.ensure_segment_count(header)
            self.ensure_fragment_count(header)

            # eprint(f"parsed header:", header.segment_id, header.aset_id, header.fragment_id)
            self.by_segment[header.segment_id].append(
                TaggedFragment(header, handle))

        if not self.by_segment:
            self.throw("Warning: No input found.")

    def segments(self):
        """Yield lists of TaggedFragments, one list per segment."""
        segment_id = 0
        for segment_id in range(self.segment_count):
            segment = self.by_segment.get(segment_id)
            if not segment:
                self.print_discovered_fragments()
                self.throw(f"No segment for segment_id={segment_id}. "
                           f"Expected {self.segment_count} segments.")
            yield segment

    def validate_aset(self, aset):
        for i in range(self.fragment_count):
            if not aset.get(i):
                self.eprint(
                    f"Warning: found aset of correct size {self.fragment_count}"
                    f", but it is missing fragment_id={i}")
                return False
        return True

    def authorized_set(self, segment):
        """Return sequence of tagged fragments of an authorized set."""
        asets = defaultdict(dict)
        for tagged_frag in segment:
            aset = asets[tagged_frag.header.aset_id]
            aset[tagged_frag.header.fragment_id] = tagged_frag
            if len(aset) == self.fragment_count and self.validate_aset(aset):
                return aset.values()
        self.throw("Warning: unable to find complete authorized set of "
                   f"size {self.fragment_count}")

    def fragments(self, authorized_set):
        frag_streams = [
            byte_seqs.resize_seqs(
                self.fragment_read_size,
                self.fragment_data_stream(tagged_frag.handle))
            for tagged_frag
            in authorized_set]
        while True:
            chunks = []
            for stream in frag_streams:
                try:
                    chunks.append(next(stream))
                except StopIteration:
                    return
            yield chunks
