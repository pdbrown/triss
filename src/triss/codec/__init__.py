from enum import IntEnum
import itertools
from collections import defaultdict, namedtuple

from triss import byte_streams
from triss import crypto
from triss.util import ErrorMessage, eprint


class Field:
    def __init__(self, name, size, default=None):
        """
        A Header field NAME that converts to SIZE bytes when serialized.
        """
        self.name = name
        self.size = size
        if default is not None:
            self.default = default

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
        return data[0:self.size]

    def generate(self, data):
        if len(data) > self.size:
            raise ValueError(
                f"Got {len(data)} bytes, which is too many to generate {self}.")
        zpadding = b'\0' * (self.size - len(data))
        return data + zpadding
        return data

class StrField(BytesField):
    default = ""
    def parse(self, data):
        return super().parse(data).decode("utf-8")

    def generate(self, s):
        return super().generate(s.encode("utf-8"))

class Header:
    @classmethod
    def size_bytes(cls):
        # Length of all fields + 2 bytes for checksum.
        return sum(field.size for field in cls.FIELDS.values()) + 2

    def __init__(self, **info):
        """
        Construct Header given INFO kwargs.

        INFO holds header data as typed objects (not just byte arrays), and is
        keyed by field names. Retrieve header bytes with get_bytes or to_bytes.
        """
        for k in self.FIELDS:
            v = info.get(k, self.FIELDS[k].default)
            setattr(self, k, v)
            # Assert values in range. get_bytes throws an OverflowError if
            # value is to big to convert.
            self.get_bytes(k)

    def __repr__(self):
        fields = [f"{k}={getattr(self, k)}" for k in self.FIELDS]
        return f"{type(self).__name__}({', '.join(fields)})"

    def get_bytes(self, k):
        """Return value of field K as byte array."""
        v = getattr(self, k)
        return self.FIELDS[k].generate(v)

    def to_bytes(self):
        """Return header as byte array."""
        data = bytes(itertools.chain.from_iterable(
            [self.get_bytes(f) for f in self.FIELDS]))
        return data + crypto.fletchers_checksum_16(data)

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
        tag = cls.FIELDS['tag'].default
        if info['tag'] != tag:
            raise ValueError(
                f"Header tag is not {tag}: is this a triss file?")
        version = cls.FIELDS['version'].default
        if info['version'] != version:
            raise ValueError(
                f"Incompatible header version, got {info['version']}' but "
                f"expected {version}")
        return cls(**info)

    @staticmethod
    def parse(byte_stream):
        """
        Parse a Header from BYTE_STREAM, an iterable of byte sequences.

        Return tuple of header and rest of BYTE_STREAM.
        """
        byte_stream = iter(byte_stream)
        for header_cls in Header.__subclasses__():
            try:
                chunk, byte_stream = byte_streams.take_and_drop(
                    header_cls.size_bytes(), byte_stream)
            except StopIteration:
                return (None, None)
            try:
                return (header_cls.from_bytes(chunk), byte_stream)
            except ValueError as e:
                # Push chunk back onto byte stream and try again
                byte_stream = itertools.chain([chunk], byte_stream)
        return (None, byte_stream)


class FragmentHeader(Header):
    VERSION = 1
    FIELDS = fields_by_name(
        BytesField("tag", 9, b'trissfrag'),
        IntField("version", 1, 1),
        IntField("aset_id", 4),
        IntField("segment_id", 4),
        IntField("segment_count", 4),
        IntField("fragment_id", 4),
        IntField("fragment_count", 4))

class MacHeader(Header):
    VERSION = 1
    FIELDS = fields_by_name(
        BytesField("tag", 8, b'trissmac'),
        IntField("version", 2, 1),
        IntField("aset_id", 4),
        # Store key for this fragment.
        IntField("fragment_id", 4),
        # Store macs for all fragments of all segments in order of ids
        IntField("segment_count", 4),
        IntField("fragment_count", 4),
        # May need to split MAC data into multiple parts (in QRCODE mode).
        # Analagous to "segments" in FragmentHeader, but don't reuse that name.
        IntField("part_id", 4),
        IntField("part_count", 4),
        # Key and digest sizes in bits
        IntField("size_bits", 4),
        StrField("algorithm", 20))


SegmentMacs = namedtuple("SegmentMacs", ["key", "hmacs"])

def aset_mac_byte_stream(fragment_id, aset_macs):
    yield aset_macs[fragment_id].key
    for segment_macs in aset_macs:
        for hmac in segment_macs.hmacs:
            yield hmac.digest()

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
        self.mac_algo = crypto.hmac_algo_name(mac_size_bits)

        self.n_asets = crypto.num_asets(m, n)
        self.n_asets_per_share = crypto.num_asets_per_share(m, n)
        self.macs = [[SegmentMacs(crypto.new_hmac_key(mac_size_bits), [])
                      for _fragment_id
                      in range(m)]
                     for _aset_id
                     in range(self.n_asets)]

    def encode_segments(self, secret_data_segments, m, n, authorized_sets):
        raise NotImplementedError()

    def summary(self, n_segments):
        self.n_segments = n_segments

    def write_hmacs(self, share_id, header, aset_macs):
        pass

    def finalize(self, share_id, header):
        pass

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
        for aset in authorized_sets:
            aset_id = aset['aset_id']
            for fragment_id, share_id in enumerate(aset['share_ids']):
                aset_macs = self.macs[aset_id]
                self.write_hmacs(share_id,
                                 MacHeader(aset_id=aset_id,
                                           fragment_id=fragment_id,
                                           segment_count=n_segments,
                                           fragment_count=m,
                                           size_bits=self.mac_size_bits,
                                           algorithm=self.mac_algo),
                                 aset_macs)
                for segment_id in range(n_segments):
                    self.finalize(share_id,
                                  FragmentHeader(aset_id=aset_id,
                                                 segment_id=segment_id,
                                                 segment_count=n_segments,
                                                 fragment_id=fragment_id,
                                                 fragment_count=m))


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
                aset_id = aset['aset_id']
                for fragment_id, (share_id, fragment) in enumerate(
                        zip(aset['share_ids'],
                            crypto.split_secret(secret_segment, m))):
                    header = FragmentHeader(aset_id=aset_id,
                                            segment_id=segment_id,
                                            fragment_id=fragment_id,
                                            fragment_count=m)
                    self.write(share_id, header, fragment)
                    seg_macs = self.macs[aset_id][fragment_id]
                    hmac = crypto.new_hmac(seg_macs.key, self.mac_size_bits)
                    hmac.update(fragment)
                    seg_macs.hmacs.append(hmac)
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

        segment_id = 0
        for secret_segment in secret_data_segments:
            for aset in authorized_sets:
                aset_id = aset['aset_id']
                for fragment_id, (share_id, fragment) in enumerate(
                        zip(aset['share_ids'],
                            crypto.split_secret(secret_segment, m))):
                    self.append(share_id, aset_id, fragment_id, fragment)
                    hmac = self.macs[aset_id][fragment_id].hmacs[segment_id]
                    hmac.update(fragment)
        # All data is appended onto 1 segment
        return 1

    def summary(self, n_segments):
        self.mapping_encoder.summary(n_segments)

    def write_hmacs(self, share_id, header, aset_macs):
        self.mapping_encoder.write_hmacs(share_id, header, aset_macs)

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

def frag_header_keyfn(tagged_frag):
    h = tagged_frag.header
    return (h.aset_id, h.segment_id, h.fragment_id)

class TaggedDecoder(Decoder):

    def __init__(self, *, fragment_read_size=4096):
        self.fragment_read_size = fragment_read_size
        self.frags_by_segment = defaultdict(list)
        self.loaded_macs = defaultdict(lambda: defaultdict(dict))

    def fragment_streams(self):
        """Return iterator over (handle, fragment_stream) pairs."""
        raise NotImplementedError()

    def fragment_data_stream(self, handle):
        """Return iterator over fragment data chunks."""
        raise NotImplementedError()

    def print_registered_headers(self):
        if self.frags_by_segment:
            self.eprint("Data fragments discovered:")
        else:
            self.eprint("No share fragments discovered.")
        for tf in sorted(itertools.chain(*self.frags_by_segment.values()),
                         key=frag_header_keyfn):
            self.eprint(f"{tf.handle}: {tf.header}")

        if self.loaded_macs:
            self.eprint("HMACs discovered:")
        else:
            self.eprint("No HMACs discovered.")
        for _aset_id, aset_macs in sorted(self.loaded_macs.items()):
            for _fragment_id, mac_parts in sorted(aset_macs.items()):
                for _part_id, tagged_frag in sorted(mac_parts.items()):
                    self.eprint(f"{tagged_frag.handle}: {tagged_frag.header}")

    def ensure_segment_count(self, header):
        if not hasattr(self, 'segment_count'):
            self.segment_count = header.segment_count
        elif self.segment_count != header.segment_count:
            self.load_error = f"Error: Inconsistent segment_count. Expected " \
                f"{self.segment_count} but got {header.segment_count} in " \
                f"{handle}"

    def register_header(self, header, handle):
        if isinstance(header, FragmentHeader):
            self.ensure_segment_count(header)
            # eprint(f"parsed header:", header.segment_id, header.aset_id, header.fragment_id)
            self.frags_by_segment[header.segment_id].append(
                TaggedFragment(header, handle))
        elif isinstance(header, MacHeader):
            aset_macs = self.loaded_macs[header.aset_id]
            mac_parts = aset_macs[header.fragment_id]
            mac_parts[header.part_id] = TaggedFragment(header, handle)
        else:
            self.eprint(
                f"Warning: Unknown header type {type(header).__name__} in "
                f"{handle}. Skipping.")

    def load(self):
        self.load_error = None
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
            self.register_header(header, handle)
        if not self.frags_by_segment:
            self.throw("Warning: No input found.")
        if self.load_error:
            self.print_registered_headers()
            self.throw(load_error)

    def segments(self):
        """Yield lists of TaggedFragments, one list per segment."""
        segment_id = 0
        for segment_id in range(self.segment_count):
            segment = self.frags_by_segment.get(segment_id)
            if not segment:
                self.print_registered_headers()
                self.throw(f"No segment for segment_id={segment_id}. "
                           f"Expected {self.segment_count} segments.")
            yield segment

    def validate_fragment_count(self, tagged_frag, expect_count):
        if tagged_frag.header.fragment_count == 0:
            self.throw(f"Error: Invalid fragment_count=0 declared in: "
                       f"{tagged_frag.handle}")
        if tagged_frag.header.fragment_count != expect_count:
            self.throw(
                f"Error: Inconsistent fragment_count. Expected "
                f"{expect_count} but got {tagged_frag.header.fragment_count} "
                f"in {tagged_frag.handle}")

    def is_complete_aset(self, aset, fragment_count):
        if len(aset) != fragment_count:
            return False
        for i in range(fragment_count):
            if not aset.get(i):
                self.eprint(
                    f"Warning: found aset of correct size {fragment_count}"
                    f", but it is missing fragment_id={i}")
                return False
        return True

    def authorized_set(self, segment):
        """Return sequence of tagged fragments of an authorized set."""
        asets = defaultdict(dict)
        fragment_count = segment[0].header.fragment_count
        for tagged_frag in segment:
            self.validate_fragment_count(tagged_frag, fragment_count)
            aset = asets[tagged_frag.header.aset_id]
            aset[tagged_frag.header.fragment_id] = tagged_frag
            if self.is_complete_aset(aset, fragment_count):
                return aset.values()
        self.throw("Warning: unable to find complete authorized set of "
                   f"size {self.fragment_count}")

    def fragments(self, authorized_set):
        frag_streams = [
            byte_streams.resize_seqs(
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
