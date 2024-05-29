from enum import IntEnum
import itertools
from collections import defaultdict, namedtuple

from triss import byte_seqs
from triss import crypto
from triss.util import ErrorMessage, eprint


class Field:
    def __init__(self, name, size):
        self.name = name
        self.size = size
    def __repr__(self):
        return f"{type(self).__name__}({self.name}, {self.size})"

def fields_by_name(*fields):
    return {f.name: f for f in fields}

class IntField(Field):
    default = 0
    def parse(self, data):
        return int.from_bytes(data[0:self.size], byteorder='big', signed=False)

    def generate(self, x):
        return x.to_bytes(length=self.size, byteorder='big', signed=False)

class BytesField(Field):
    default = b''
    def parse(self, data):
        if len(data) < self.size:
            raise ValueError(
                f"Can't parse {self.name} field, need {self.size} bytes but "
                f"only got {len(data)}.")
        return data[0:self.size]

    def generate(self, data):
        return data

class StrField(BytesField):
    default = ""
    def parse(self, data):
        return super().parse(data).decode("utf-8")

    def generate(self, s):
        data = s.encode("utf-8")
        if len(data) > self.size:
            raise ValueError(
                f'Got too many bytes encoding utf-8 string "{s}" for {self}.')
        zpadding = b'\0' * (self.size - len(data))
        return data + zpadding

class Header:
    @classmethod
    def size_bytes(cls):
        # Length of all fields + 2 bytes for checksum.
        return sum(field.size for field in cls.FIELDS.values()) + 2

    def __init__(self, info):
        """
        Construct Header given INFO dictionary.

        INFO holds header data as typed objects (not just byte arrays), and is
        keyed by strings in the self.fields() array. Retrieve header bytes with
        get_bytes or to_bytes.
        """
        self.info = info
        info['tag'] = self.FIELDS['tag'].parse(self.TAG)
        if not 'version' in info:
            raise ValueError("Header info must contain 'version'")
        for k in self.FIELDS:
            # Initialize to zero if undefined
            if k not in info:
                info[k] = self.FIELDS[k].default
            # Assert values in range. get_bytes throws an OverflowError if
            # value is to big to convert.
            self.get_bytes(k)

    def get_bytes(self, k):
        """Return value of field K as byte array."""
        v = self.info[k]
        return self.FIELDS[k].generate(v)

    @property
    def version(self):
        return self.info['version']

    def to_bytes(self):
        """Return header as byte array."""
        data = bytes(itertools.chain.from_iterable(
            [self.get_bytes(f) for f in self.FIELDS]))
        return data + crypto.fletchers_checksum_16(data)

    @classmethod
    def create(cls, **info):
        """Construct Header from INFO at current Header.VERSION."""
        info['version'] = cls.VERSION
        return cls(info)

    @classmethod
    def from_bytes(cls, data):
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
        for k, field in cls.FIELDS.items():
            info[k] = field.parse(payload[i:i+field.size])
            i += field.size
        if info['tag'] != cls.TAG:
            raise ValueError(
                f"Header tag is not {cls.TAG}: is this a triss file?")
        if info['version'] != cls.VERSION:
            raise ValueError(
                f"Incompatible header version, got {info['version']}' but "
                f"expected {cls.VERSION}")
        return cls.create(**info)

    @staticmethod
    def parse(byte_stream):
        """
        Parse a Header from BYTE_STREAM, an iterable of byte sequences.

        Return tuple of header and rest of BYTE_STREAM.
        """
        byte_stream = iter(byte_stream)
        for header_cls in Header.__subclasses__():
            try:
                chunk, byte_stream = byte_seqs.take_and_drop(
                    header_cls.size_bytes(), byte_stream)
            except StopIteration:
                return (None, None)
            try:
                return (header_cls.from_bytes(chunk), byte_stream)
            except ValueError as e:
                # Put chunk back onto byte seqs and try again
                byte_stream = itertools.chain([chunk], byte_stream)
        return (None, byte_stream)


class FragmentHeader(Header):
    TAG = b'trissfrag'
    VERSION = 1
    FIELDS = fields_by_name(
        BytesField("tag", 9),
        IntField("version", 1),
        IntField("aset_id", 4),
        IntField("segment_id", 4),
        IntField("segment_count", 4),
        IntField("fragment_id", 4),
        IntField("fragment_count", 4))

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


class MacHeader(Header):
    TAG = b'trissmac'
    VERSION = 1
    FIELDS = fields_by_name(
        BytesField("tag", 8),
        IntField("version", 2),
        IntField("share_count", 4),
        IntField("part_id", 4),
        IntField("part_count", 4),
        IntField("size", 4),
        StrField("algorithm", 20))

    @property
    def share_count(self):
        return self.info['share_count']

    @property
    def part_id(self):
        return self.info['part_id']

    @property
    def part_count(self):
        return self.info['part_count']

    @property
    def size(self):
        return self.info['size']

    @property
    def algorithm(self):
        return self.info['algorithm']

class Encoder:
    # Implementor's Interface
    def configure(self, m, n, mac_size_bits):
        if m < 2 or n < 2:
            raise ErrorMessage("Must split into at least 2 shares.")
        if m > n:
            raise ErrorMessage("M cannot be larger than N for M-of-N split: "
                               f"got M={m} of N={n}")
        self.m = m
        self.n = n
        self.mac_size_bits = mac_size_bits
        self.macs = [crypto.new_hmac(size_bits=mac_size_bits)
                     for share_id
                     in range(self.n)]

    def encode_segments(self, secret_data_segments, m, n, authorized_sets):
        raise NotImplementedError()

    def summary(self, n_segments):
        self.n_segments = n_segments
        self.n_asets = crypto.num_asets(self.m, self.n)
        self.fragments_per_share = crypto.num_fragments_per_share(self.m, self.n)
        self.n_fragments = self.n_segments * self.fragments_per_share

    def write_hmacs(self):
        pass

    def finalize(self, share_id, header):
        pass

    # Helpers
    def hmac_byte_stream(self, share_id):
        yield self.macs[share_id].key
        for mac_id in range(self.n):
            yield self.macs[mac_id].hmac.digest()

    # Entrypoint
    def encode(self, secret_data_segments, m, n, *,
               mac_size_bits=crypto.DEFAULT_MAC_SIZE_BITS):
        self.configure(m, n, mac_size_bits)
        authorized_sets = crypto.m_of_n_access_structure(m, n)
        n_segments = self.encode_segments(
            secret_data_segments, m, n, authorized_sets)
        if n_segments == 0:
            return
        self.summary(n_segments)
        self.write_hmacs()
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
                    self.macs[share_id].hmac.update(fragment)
        return n_segments


class AppendingEncoder(Encoder):

    def __init__(self, mapping_encoder):
        self.mapping_encoder = mapping_encoder

    def configure(self, m, n, mac_size_bits):
        super().configure(m, n, mac_size_bits)
        self.mapping_encoder.configure(m, n, mac_size_bits)
        # Make sure we use the same macs for all segments. Ignore and gc the
        # macs initialized in super().configure. This class' encode_segments
        # implementation calls mapping_encoder.write once, which will update
        # mapping_encoder.macs, then updates self.macs 0 or more times.
        self.macs = self.mapping_encoder.macs

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
                    self.macs[share_id].hmac.update(fragment)
        # All data is appended onto 1 segment
        return 1

    def summary(self, n_segments):
        self.mapping_encoder.summary(n_segments)

    def write_hmacs(self):
        self.mapping_encoder.write_hmacs()

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

    def macs(self):
        return []

    # Entrypoint
    def decode(self):
        self.load()
        for segment in self.segments():
            authorized_set = self.authorized_set(segment)
            for chunk_fragments in self.fragments(authorized_set):
                yield crypto.combine_fragments(chunk_fragments)
        # for mac in self.macs():
        #     decode_digest = mac.hmac.digest()
        #     if not crypto.digests_equal(decode_digest, mac.digest):
        #         self.throw(
        #             "DANGER: Digests don't match, can't prove reconstructed "
        #             "secret is the same as the original.")


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
            header, frag_stream = Header.parse(frag_stream)
            if header is None:
                if frag_stream is None:
                    self.eprint("Warning: No data in file, can't parse header: "
                                f"{handle}. Skipping.")
                else:
                    self.eprint(f"Warning: Failed to parse header: {handle}. "
                                "Skipping.")
                continue
            if isinstance(header, FragmentHeader):
                self.ensure_segment_count(header)
                self.ensure_fragment_count(header)
                # eprint(f"parsed header:", header.segment_id, header.aset_id, header.fragment_id)
                self.by_segment[header.segment_id].append(
                    TaggedFragment(header, handle))
            elif isinstance(header, MacHeader):
                print("GOT MAC HEADER:", header)
            else:
                self.eprint(
                    f"Warning: Unknown header type {type(header).__name__} in "
                    f"{handle}. Skipping.")

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
        hmacs = range(999999)
        # hmacs = [
        #      self_get.macs[tagged_frag.header.share_id].hmac
        #      for tagged_frag
        #      in authorized_set]
        while True:
            chunks = []
            for stream, hmac in zip(frag_streams, hmacs):
                try:
                    chunk = next(stream)
                    chunks.append(chunk)
                    # hmac.update(chunk)
                except StopIteration:
                    return
            yield chunks
