# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from enum import IntEnum
import itertools
from collections import defaultdict, namedtuple

from triss import byte_streams
from triss import crypto
from triss.util import eprint, print_exception, verbose


###############################################################################
# Header

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
                f"Got {len(data)} bytes, which is too many to generate "
                f"{self}.")
        zpadding = b'\0' * (self.size - len(data))
        return data + zpadding
        return data

class StrField(BytesField):
    default = ""
    def parse(self, data):
        return super().parse(data).decode('utf-8').rstrip("\0")

    def generate(self, s):
        return super().generate(s.encode('utf-8'))

class Header:
    def __init__(self, **info):
        """
        Construct Header given INFO kwargs.

        INFO holds header data as typed objects (not just byte arrays), and is
        keyed by field names. Retrieve header bytes with get_bytes or to_bytes.
        """
        for k in self.__fields__:
            v = info.get(k, self.__fields__[k].default)
            setattr(self, k, v)
            # Assert values in range. get_bytes throws an OverflowError if
            # value is to big to convert.
            self.get_bytes(k)

    def __repr__(self):
        fields = [f"{k}={getattr(self, k)}" for k in self.__fields__]
        return f"{type(self).__name__}({', '.join(fields)})"

    def __iter__(self):
        for k in self.__fields__:
            yield getattr(self, k)

    def get_bytes(self, k):
        """Return value of field K as byte array."""
        v = getattr(self, k)
        return self.__fields__[k].generate(v)

    def to_bytes(self):
        """Return header as byte array."""
        data = bytes(itertools.chain.from_iterable(
            [self.get_bytes(k) for k in self.__fields__]))
        return data + crypto.fletchers_checksum_16(data)

    @classmethod
    def size_bytes(cls):
        # Length of all fields + 2 bytes for checksum.
        return sum(field.size for field in cls.__fields__.values()) + 2

    @classmethod
    def from_bytes(cls, data):
        """Parse byte array DATA and return instance of Header."""
        size = cls.size_bytes()
        if len(data) < size:
            raise ValueError(
                f"{cls.__name__}: Can't parse header, got {len(data)} bytes "
                f"but needed {size} bytes.")
        data = data[0:size]
        checksum = bytes(data[-2:])  # last 2 bytes are checksum
        payload = bytes(data[0:-2])  # first n-2 bytes are payload
        if crypto.fletchers_checksum_16(payload) != checksum:
            raise ValueError(
                f"{cls.__name__}: Refusing to parse header with bad checksum.")
        info = {}
        i = 0
        for k, field in cls.__fields__.items():
            info[k] = field.parse(payload[i:i+field.size])
            i += field.size
        tag = cls.__fields__['tag'].default
        if info['tag'] != tag:
            raise ValueError(
                f"{cls.__name__}: Header tag is not {tag.decode('utf-8')}: is "
                "this a triss file?")
        version = cls.__fields__['version'].default
        if info['version'] != version:
            raise ValueError(
                f"{cls.__name__}: Incompatible header version, got "
                f"{info['version']} but expected {version}")
        return cls(**info)

    @staticmethod
    def parse(byte_stream):
        """
        Parse a Header from BYTE_STREAM, an iterable of byte sequences.

        Return tuple of header and rest of BYTE_STREAM.
        """
        exceptions = []
        byte_stream = iter(byte_stream)
        for header_cls in Header.__subclasses__():
            try:
                chunk, byte_stream = byte_streams.take_and_drop(
                    header_cls.size_bytes(), byte_stream)
            except StopIteration as e:
                raise ValueError("No data available.") from e
            if not chunk:
                raise ValueError("No data available.")
            try:
                return (header_cls.from_bytes(chunk), byte_stream)
            except ValueError as e:
                exceptions.append(e)
                # Push chunk back onto byte stream and try again
                byte_stream = itertools.chain([chunk], byte_stream)
        raise ExceptionGroup("Data doesn't match any Header format.",
                             exceptions)


class FragmentHeader(Header):
    __fields__ = fields_by_name(
        BytesField("tag", 9, b'trissfrag'),
        IntField("version", 1, 1),
        IntField("payload_size", 4),
        IntField("aset_id", 4),
        IntField("segment_id", 4),
        IntField("segment_count", 4),
        IntField("fragment_id", 4),
        IntField("fragment_count", 4))

class MacHeader(Header):
    __fields__ = fields_by_name(
        BytesField("tag", 8, b'trissmac'),
        IntField("version", 2, 1),
        IntField("aset_id", 4),
        # Store key for this fragment.
        IntField("fragment_id", 4),
        # Store macs for all fragments of all segments in order of ids
        IntField("segment_count", 4),
        IntField("fragment_count", 4),
        # May need to split MAC data into multiple "slices" (in QRCODE mode).
        # Analagous to "segments" in FragmentHeader, but don't reuse that name.
        IntField("part_id", 4),
        IntField("part_count", 4),
        IntField("key_size_bytes", 4),
        StrField("algorithm", 24))


###############################################################################
# Encoder


KeyedMacs = namedtuple("KeyedMacs", ["key", "macs"])

class Encoder:

    DEFAULT_MAC_ALGORITHM="hmac-sha384"

    def configure(self, m, n, mac_algorithm):
        if m < 2 or n < 2:
            raise ValueError("Must split into at least 2 shares.")
        if m > n:
            raise ValueError("M cannot be larger than N for M-of-N split: "
                             f"got M={m} of N={n}")
        self.m = m
        self.n = n
        self.mac_algorithm = mac_algorithm

        self.n_asets = crypto.num_asets(m, n)
        self.n_asets_per_share = crypto.num_asets_per_share(m, n)
        self.macs = [[KeyedMacs(crypto.new_mac_key(mac_algorithm), [])
                      for _fragment_id
                      in range(m)]
                     for _aset_id
                     in range(self.n_asets)]
        self.mac_key_size_bytes = len(self.macs[0][0].key)

    def encode_segments(self, secret_data_segments, m, n, authorized_sets):
        raise NotImplementedError()

    def summary(self, n_segments):
        self.n_segments = n_segments

    def write_macs(self, share_id, header, mac_data_stream):
        pass

    def patch_header(self, share_id, header_key, n_segments):
        pass

    # Helpers
    def aset_mac_byte_stream(self, aset_id, fragment_id, n_segments):
        aset_macs = self.macs[aset_id]
        yield aset_macs[fragment_id].key
        for segment_id in range(n_segments):
            for fragment_macs in aset_macs:
                mac = fragment_macs.macs[segment_id]
                yield mac.digest()

    # Entrypoint
    def encode(self, secret_data_segments, m, n, *,
               mac_algorithm=DEFAULT_MAC_ALGORITHM):
        self.configure(m, n, mac_algorithm)
        authorized_sets = crypto.m_of_n_access_structure(m, n)
        n_segments = self.encode_segments(
            secret_data_segments, m, n, authorized_sets)
        if n_segments == 0:
            return
        self.summary(n_segments)
        for aset in authorized_sets:
            aset_id = aset['aset_id']
            for fragment_id, share_id in enumerate(aset['share_ids']):
                self.write_macs(
                    share_id,
                    MacHeader(aset_id=aset_id,
                              fragment_id=fragment_id,
                              segment_count=n_segments,
                              fragment_count=m,
                              part_id=0,
                              part_count=1,
                              key_size_bytes=self.mac_key_size_bytes,
                              algorithm=self.mac_algorithm),
                    self.aset_mac_byte_stream(aset_id, fragment_id,
                                              n_segments))
                for segment_id in range(n_segments):
                    self.patch_header(
                        share_id,
                        FragmentHeader(aset_id=aset_id,
                                       segment_id=segment_id,
                                       fragment_id=fragment_id),
                        n_segments)


class MappingEncoder(Encoder):

    def write(self, share_id, header, fragment):
        raise NotImplementedError()

    def add_mac(self, aset_id, fragment_id, fragment):
        share_mac = self.macs[aset_id][fragment_id]
        mac = crypto.new_mac(share_mac.key, self.mac_algorithm)
        mac.update(fragment)
        share_mac.macs.append(mac)

    def encode_segments(self, secret_data_segments, m, n, authorized_sets):
        n_segments = 0
        for segment_id, secret_segment in enumerate(secret_data_segments):
            n_segments += 1
            payload_size = len(secret_segment)
            for aset in authorized_sets:
                aset_id = aset['aset_id']
                for fragment_id, (share_id, fragment) in enumerate(
                        zip(aset['share_ids'],
                            crypto.split_secret(secret_segment, m))):
                    header = FragmentHeader(payload_size=payload_size,
                                            aset_id=aset_id,
                                            segment_id=segment_id,
                                            fragment_id=fragment_id,
                                            fragment_count=m)
                    self.write(share_id, header, fragment)
                    self.add_mac(aset_id, fragment_id, fragment)
        return n_segments

class AppendingEncoder(Encoder):

    def __init__(self, mapping_encoder):
        self.mapping_encoder = mapping_encoder

    def configure(self, m, n, mac_algorithm):
        super().configure(m, n, mac_algorithm)
        self.mapping_encoder.configure(m, n, mac_algorithm)
        # Make sure we use the same macs for all segments. Ignore and gc the
        # macs initialized in super().configure. This class' encode_segments
        # implementation calls mapping_encoder.write once, which will update
        # mapping_encoder.macs, then updates self.macs 0 or more times.
        self.macs = self.mapping_encoder.macs
        self.byte_counts = defaultdict(int)

    def append(self, share_id, aset_id, fragment_id, fragment):
        raise NotImplementedError()

    def patch_append_size(self, share_id, header_key, appended_byte_count):
        raise NotImplementedError()

    def update_mac(self, aset_id, fragment_id, fragment):
        segment_id = 0  # Appending encoder appends to first and only segment
        share_mac = self.macs[aset_id][fragment_id]
        share_mac.macs[segment_id].update(fragment)

    def encode_segments(self, secret_data_segments, m, n, authorized_sets):
        secret_data_segments = iter(secret_data_segments)
        try:
            first_segment = next(secret_data_segments)
        except StopIteration:
            # No segments available
            return 0

        n_segments = self.mapping_encoder.encode_segments(
            [first_segment], m, n, authorized_sets)

        segment_id = 0
        for secret_segment in secret_data_segments:
            for aset in authorized_sets:
                aset_id = aset['aset_id']
                for fragment_id, (share_id, fragment) in enumerate(
                        zip(aset['share_ids'],
                            crypto.split_secret(secret_segment, m))):
                    self.append(share_id, aset_id, fragment_id, fragment)
                    self.update_mac(aset_id, fragment_id, fragment)
                    self.byte_counts[(aset_id, fragment_id)] += \
                        len(secret_segment)
        return n_segments

    def summary(self, n_segments):
        self.mapping_encoder.summary(n_segments)

    def write_macs(self, share_id, header, mac_data_stream):
        self.mapping_encoder.write_macs(share_id, header, mac_data_stream)

    def patch_header(self, share_id, header_key, n_segments):
        k = (header_key.aset_id, header_key.fragment_id)
        self.patch_append_size(share_id, header_key, self.byte_counts[k])
        self.mapping_encoder.patch_header(share_id, header_key, n_segments)



###############################################################################
# Decoder

class MacWarning(Exception):
    pass

LoadedMac = namedtuple("LoadedMac", ["key", "digest", "algorithm"])
TaggedInput = namedtuple("TaggedInput", ["header", "handle"])

def frag_header_keyfn(tagged_input):
    h = tagged_input.header
    return (h.aset_id, h.segment_id, h.fragment_id)


class Decoder:

    def __init__(self, *, fragment_read_size=(4096*16)):
        self.fragment_read_size = fragment_read_size
        self.name = type(self).__name__

    def input_streams(self):
        """Return iterator over (handle, input_stream) pairs."""
        raise NotImplementedError()

    def payload_stream(self, tagged_input):
        """
        Return iterator over data chunks of payload of TAGGED_INPUT.

        I.e. skip the header, then return rest of data.
        """
        raise NotImplementedError()

    # Helpers
    def eprint(self, *args):
        eprint(f"{self.name}:", *args)

    # Implementation
    def print_registered_headers(self):
        if self.frags_by_segment:
            self.eprint("Found data fragments:")
        else:
            self.eprint("No data fragments discovered.")
        for header, handle in sorted(
                itertools.chain(*self.frags_by_segment.values()),
                key=frag_header_keyfn):
            self.eprint(f"{handle}: {header}")

        if self.mac_parts:
            self.eprint("Found MAC inputs:")
        else:
            self.eprint("No MACs discovered.")
        for _aset_id, aset_macs in sorted(self.mac_parts.items()):
            for _fragment_id, mac_parts in sorted(aset_macs.items()):
                for _part_id, (header, handle) in sorted(mac_parts.items()):
                    self.eprint(f"{handle}: {header}")

    @staticmethod
    def validate_header_attr(tagged_input, attr, expect):
        header, handle = tagged_input
        attr_val = getattr(header, attr)
        if attr_val != expect:
            raise ValueError(
                f"Inconsistent {attr}. Expected {expect} but got {attr_val} "
                f"in header of {handle}: {header}")

    def ensure_segment_count(self, header, handle):
        if not hasattr(self, 'segment_count'):
            if header.segment_count == 0:
                raise ValueError(
                    f"Invalid segment_count=0 in header of {handle}: {header}")
            self.segment_count = header.segment_count
        self.validate_header_attr((header, handle), 'segment_count',
                                  self.segment_count)

    def register_header(self, header, handle):
        if isinstance(header, FragmentHeader):
            self.frags_by_segment[header.segment_id].append(
                TaggedInput(header, handle))
            self.ensure_segment_count(header, handle)
        elif isinstance(header, MacHeader):
            aset_macs = self.mac_parts[header.aset_id]
            fragment_macs = aset_macs[header.fragment_id]
            fragment_macs[header.part_id] = TaggedInput(header, handle)
        else:
            raise ValueError(
                f"Unknown header type {type(header).__name__}.")

    def load(self):
        for handle, input_stream in self.input_streams():
            try:
                header, input_stream = Header.parse(input_stream)
            except Exception as e:
                self.eprint(f"Unable to parse header in {handle}, skipping it."
                            " Parsing failed with:")
                print_exception(e)
                continue
            try:
                self.register_header(header, handle)
            except Exception as e:
                self.eprint(f"Unable to register header in {handle}, skipping it."
                            " Failed with:")
                print_exception(e)
                continue
        if not self.frags_by_segment or not hasattr(self, 'segment_count'):
            raise RuntimeError("No input found.")

    def segments(self):
        """Yield lists of TaggedInputs, one list per segment."""
        segment_id = 0
        for segment_id in range(self.segment_count):
            try:
                segment = self.frags_by_segment[segment_id]
            except KeyError as e:
                raise ValueError(
                    f"Missing segment for {segment_id=}. Expected "
                    f"{self.segment_count} segments.") from e
            yield segment

    def is_complete_aset(self, aset, fragment_count):
        if len(aset) != fragment_count:
            return False
        for i in range(fragment_count):
            if not aset.get(i):
                self.eprint(
                    f"Found authorized set of correct size {fragment_count}, "
                    f"but it is missing fragment_id={i}")
                return False
        return True

    def authorized_set(self, segment_id, segment):
        """Return sequence of tagged fragments of an authorized set."""
        asets = defaultdict(dict)
        if not segment:
            raise ValueError(
                f"Segment {segment_id=} is empty (contains no fragments), so "
                "it's impossible to find an authorized set of fragments to "
                "decrypt it.")
        fragment_count = segment[0].header.fragment_count
        payload_size = segment[0].header.payload_size
        for tagged_input in segment:
            self.validate_header_attr(tagged_input, 'fragment_count',
                                      fragment_count)
            self.validate_header_attr(tagged_input, 'payload_size',
                                      payload_size)
            aset = asets[tagged_input.header.aset_id]
            aset[tagged_input.header.fragment_id] = tagged_input
            if self.is_complete_aset(aset, fragment_count):
                return list(aset.values())
        raise RuntimeError(
            f"Unable to find complete authorized set of size {fragment_count} "
            f"for segment {segment_id=}")

    def fragments(self, authorized_set):
        input_streams = [
            byte_streams.resize_seqs(
                self.fragment_read_size,
                self.payload_stream(tagged_input))
            for tagged_input
            in authorized_set]
        while True:
            chunks = []
            for stream in input_streams:
                try:
                    chunks.append(next(stream))
                except StopIteration:
                    return
            yield chunks

    def validate_mac_header(self, tagged_input, fragment_count, part_count):
        header, handle = tagged_input
        self.validate_header_attr(tagged_input, 'segment_count',
                                  self.segment_count)
        self.validate_header_attr(tagged_input, 'fragment_count',
                                  fragment_count)
        self.validate_header_attr(tagged_input, 'part_count', part_count)
        key_size = header.key_size_bytes
        if key_size > crypto.MAX_KEY_SIZE:
            raise ValueError(
                f"Unable to construct MAC for algorithm {header.algorithm} "
                f"with key of size {key_size}, key is to big, max size is "
                f"{crypto.MAX_KEY_SIZE}. Requested in header of {handle}: "
                f"{header}")
        try:
            crypto.new_mac(b'\0' * key_size, header.algorithm)
        except Exception as e:
            raise ValueError(
                f"Unable to construct MAC for algorithm {header.algorithm} "
                f"with key of size {key_size} requested in header of {handle}:"
                f" {header}") from e

    def concat_mac_parts(self, mac_parts, aset_id, fragment_id,
                         fragment_count):
        # mac_parts is dict: {part_id: part}
        part_count = len(mac_parts)
        for part_id in range(part_count):
            try:
                part = mac_parts[part_id]
            except KeyError as e:
                raise ValueError(
                    f"Missing MAC part {part_id+1}/{part_count} for fragment "
                    f"{fragment_id=} of authorized set {aset_id=}") from e
            self.validate_mac_header(part, fragment_count, part_count)
        header0 = mac_parts[0].header
        payload = b''
        for part_id in range(part_count):
            tagged_input = mac_parts[part_id]
            for chunk in self.payload_stream(tagged_input):
                payload += chunk
        return (header0, payload)

    def index_macs(self, headers_keys, mac_data, fragment_count, aset_id):
        cursor = 0
        for segment_id in range(self.segment_count):
            assert segment_id not in self.loaded_macs[aset_id]
            macs = []
            self.loaded_macs[aset_id][segment_id] = macs
            for fragment_id in range(fragment_count):
                (header, key) = headers_keys[fragment_id]
                digest_size = crypto.digest_size_bytes(header.algorithm)
                digest = mac_data[cursor:cursor+digest_size]
                cursor += digest_size
                macs.append(LoadedMac(key, digest, header.algorithm))
        if cursor != len(mac_data):
            self.eprint(
                f"Warning: Finished reading {cursor} bytes of MAC digest data "
                f"for {self.segment_count} segments of all {fragment_count} "
                f"fragments of authorized set {aset_id=}, but had "
                f"{len(mac_data)} bytes available and expected to read all "
                "bytes.")

    def load_macs(self, aset_id, segment_id, fragment_count):
        def ensure_mac_count(macs):
            if len(macs) != fragment_count:
                raise ValueError(
                    f"Expected a MAC for each of {fragment_count} fragments "
                    f"but got {len(macs)} instead.")
            return macs

        try:
            return ensure_mac_count(self.loaded_macs[aset_id][segment_id])
        except KeyError:
            pass
        try:
            aset_macs = self.mac_parts[aset_id]
        except KeyError as e:
            raise ValueError(
                f"No MACs available for authorized set {aset_id=}") from e

        def fragment_mac_info(fragment_id):
            try:
                mac_parts = aset_macs[fragment_id]
            except KeyError as e:
                mac_parts = []
            if not mac_parts:
                raise ValueError(
                    f"No MAC key or digests available for {fragment_id=} of "
                    f"authorized set {aset_id=}")
            # data holds key for MAC digests of all segments of fragment_id,
            # and MAC digests for all segments of all fragments of the aset.
            (header, data) = self.concat_mac_parts(
                mac_parts, aset_id, fragment_id, fragment_count)
            data = memoryview(data)
            key = data[0:header.key_size_bytes]
            mac_data = data[header.key_size_bytes:]
            return (header, key, mac_data)

        fragment_id = 0
        (header0, key0, mac_data0) = fragment_mac_info(fragment_id)
        infos = [(header0, key0)]

        for fragment_id in range(1, fragment_count):
            (header, key, mac_data) = fragment_mac_info(fragment_id)
            if mac_data != mac_data0:
                raise ValueError(
                    f"Invalid MAC data for {fragment_id=} of authorized set "
                    f"{aset_id=} in {segment_id=}. Each share received an "
                    "identical copy of the MACs computed for each segment of "
                    "each fragment of the authorized set, but the copy of the "
                    "MACs assigned to the share of the reported fragment does "
                    "not match the others.")
            infos.append((header, key))
        self.index_macs(infos, mac_data0, fragment_count, aset_id)
        return ensure_mac_count(self.loaded_macs[aset_id][segment_id])

    def combine_fragments(self, authorized_set, segment_id,
                          ignore_mac_error=False):
        macs_valid = True
        def mac_error(msg, cause=None):
            nonlocal macs_valid
            macs_valid = False
            if ignore_mac_error:
                self.eprint(
                    f"WARNING: {msg}" + (f": {cause}" if cause else ""))
            else:
                self.eprint(msg)
                raise RuntimeError(
                    f"{self.name}: ERROR: Unable to verify authenticity of "
                    "output. Aborting any remaining decoding process. Use "
                    "extreme caution handling any partial output, it "
                    "may have been modified by an attacker.") from cause

        if not authorized_set:
            raise ValueError(
                "Authorized is empty (contains no fragments), so it's "
                "impossible to find an authorized set of fragments to decrypt "
                "it.")

        # While fragments of authorized_set can be combined in any order, MACs
        # are loaded in fragment_id order. Sort fragments the same way so
        # zip(fragments, macs) pairs each fragment with the matching MAC.
        authorized_set = sorted(authorized_set,
                                key=lambda tf: tf.header.fragment_id)
        aset_id = authorized_set[0].header.aset_id
        payload_size = authorized_set[0].header.payload_size
        try:
            loaded_macs = self.load_macs(aset_id, segment_id,
                                         len(authorized_set))
        except Exception as e:
            mac_error(
                f"Failed to load MACs while decoding segment {segment_id=} "
                f"with authorized set {aset_id=}",
                cause=e)
            loaded_macs = []

        n_bytes = 0
        computed_macs = [crypto.new_mac(mac.key, mac.algorithm)
                         for mac
                         in loaded_macs]
        for fragment_chunks in self.fragments(authorized_set):
            for (frag_chunk, mac) in zip(fragment_chunks, computed_macs):
                mac.update(frag_chunk)
            output_chunk = crypto.combine_fragments(fragment_chunks)
            n_bytes += len(output_chunk)
            yield output_chunk
        if payload_size != n_bytes:
            raise ValueError(
                f"Expected to decode {payload_size} bytes, but decoded "
                f"{n_bytes} bytes of {segment_id=} of authorized set "
                f"{aset_id=}")
        for fragment_id, (loaded_mac, computed_mac) in enumerate(
                zip(loaded_macs, computed_macs)):
            if not crypto.digests_equal(loaded_mac.digest,
                                        computed_mac.digest()):
                mac_error(
                    f"MAC digest mismatch for {fragment_id=} of {segment_id=} "
                    f"authorized set {aset_id=}")
        return macs_valid

    # Entrypoint
    def decode(self, ignore_mac_error=False):
        # segment_id -> [TaggedInput]
        self.frags_by_segment = defaultdict(list)
        # aset_id -> fragment_id -> part_id -> TaggedInput
        self.mac_parts = defaultdict(lambda: defaultdict(dict))
        # aset_id -> segment_id -> [LoadedMac] in fragment_id order
        self.loaded_macs = defaultdict(dict)

        macs_valid = True
        try:
            self.load()
        finally:
            self.print_registered_headers()
        for segment_id, segment in enumerate(self.segments()):
            authorized_set = self.authorized_set(segment_id, segment)
            ret = yield from self.combine_fragments(
                authorized_set, segment_id, ignore_mac_error)
            macs_valid = ret and macs_valid
        if not macs_valid:
            raise MacWarning()
