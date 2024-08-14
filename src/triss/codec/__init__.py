# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import itertools
from collections import defaultdict, namedtuple
import sys

from triss import byte_streams
from triss import crypto
from triss.header import FragmentHeader, MacHeader
from triss.util import eprint, print_exception


###############################################################################
# Encoder

class Writer:
    """
    An Encoder uses a Writer to emit output.
    """

    def write(self, share_id, header, payload=None):
        """
        Write an output with HEADER and PAYLOAD bytes to share SHARE_ID.

        If paylod is None (over)write just the HEADER.
        """
        raise NotImplementedError()

    def summary(self, encoder):
        """
        Called after all outputs have been written, before post_process().
        """
        pass

    def post_process(self, header):
        """
        Called at the end of encoding, once for each output. HEADER now has
        a metadata object that includes the share_id at
        header.metadata.share_id.
        """
        pass


class Appender(Writer):
    """
    An Appender is a Writer that can also append payload data

    to previously written outputs.
    """
    def append(self, share_id, header, chunk):
        """
        Append CHUNK bytes to the output identified by HEADER in share
        SHARE_ID.
        """
        raise NotImplementedError()


KeyedMacs = namedtuple("KeyedMacs", ["key", "macs"])


class Encoder:
    """
    Use an Encoder to split a secret into encrypted shares with authenticated

    M-of-N trivial secret sharing. An Encoder produces a set of split,
    encrypted, output fragments for each element of secret_data_segments
    provided to the encode(secret_data_segments, m, n) method.
    """

    DEFAULT_MAC_ALGORITHM = "hmac-sha384"

    def __init__(self, writer, *,
                 mac_algorithm=DEFAULT_MAC_ALGORITHM,
                 mac_slice_size_bytes=(64*1024)):
        if writer is None:
            raise ValueError("Must provide writer.")
        self.writer = writer
        self.mac_algorithm = mac_algorithm
        self.mac_slice_size_bytes = mac_slice_size_bytes

    def configure(self, m, n):
        if n is None:
            raise ValueError("Must provide total number of shares N.")
        if m is None:
            m = n
        if m < 2 or n < 2:
            raise ValueError("Must split into at least 2 shares.")
        if m > n:
            raise ValueError("M cannot be larger than N for M-of-N split: "
                             f"got M={m} of N={n}")
        self.m = m
        self.n = n

        self.n_asets = crypto.num_asets(m, n)
        self.n_asets_per_share = crypto.num_asets_per_share(m, n)

        # header_key -> Header
        # header_key is a tuple obtained from Header.to_key().
        self.headers = {}

        # aset_id -> fragment_id -> KeyedMacs(frag_key, segment_id -> hmac)
        # list[list[KeyedMacs(key, list[hmac])]]
        self.macs = [[KeyedMacs(crypto.new_mac_key(self.mac_algorithm), [])
                      for _fragment_id
                      in range(m)]
                     for _aset_id
                     in range(self.n_asets)]
        self.mac_key_size_bytes = len(self.macs[0][0].key)

    def add_mac(self, aset_id, fragment_id, fragment):
        """
        Create a new Mac object for a next segment of fragment FRAGMENT_ID

        of authorized set ASET_ID with split, encrypted FRAGMENT data, mix
        FRAGMENT data into its digest, and add it to the self.macs index.
        """
        fragment_macs = self.macs[aset_id][fragment_id]
        mac = crypto.new_mac(fragment_macs.key, self.mac_algorithm)
        mac.update(fragment)
        fragment_macs.macs.append(mac)

    def encode_segments(self, secret_data_segments, authorized_sets):
        """
        Split secret into shares.

        Take an iterable of SECRET_DATA_SEGMENTS (byte sequences), split them
        into shares according to the AUTHORIZED_SETS determined by values of M
        and N which specify an M-of-N secret sharing scheme. See also
        triss.crypto.
        """
        n_segments = 0
        for segment_id, secret_segment in enumerate(secret_data_segments):
            n_segments += 1
            payload_size = len(secret_segment)
            for aset in authorized_sets:
                aset_id = aset['aset_id']
                for fragment_id, (share_id, fragment) in enumerate(
                        zip(aset['share_ids'],
                            crypto.split_secret(secret_segment, self.m))):
                    header = FragmentHeader(payload_size=payload_size,
                                            aset_id=aset_id,
                                            segment_id=segment_id,
                                            fragment_id=fragment_id,
                                            fragment_count=self.m)
                    header.metadata.share_id = share_id
                    self.headers[header.to_key()] = header
                    self.writer.write(share_id, header, fragment)
                    self.add_mac(aset_id, fragment_id, fragment)
        return n_segments

    def patch_headers(self, n_segments):
        """
        Rewrite and compute MACs of all fragment headers.

        Called after encode_segments. For each header:
        - Set each its n_segments field now that it's known.
        - Rewrite it.
        - Mix the header bytes into the MAC digest of the corresponding
          fragment.
        """
        for header in self.headers.values():
            header.segment_count = n_segments
            self.writer.write(header.metadata.share_id, header)
            try:
                mac = self.macs[header.aset_id][header.fragment_id] \
                          .macs[header.segment_id]
            except KeyError:
                mac = None
            if mac:
                mac.update(header.to_bytes())

    def aset_mac_byte_stream(self, aset_id, fragment_id, n_segments):
        """
        Return a byte stream of MAC data (a generator that yields byte sequences)

        for all fragments of all segments of authorized set ASET_id, and
        includes the MAC key for fragment FRAGMENT_ID.
        """
        aset_macs = self.macs[aset_id]
        yield aset_macs[fragment_id].key
        for segment_id in range(n_segments):
            for fragment_macs in aset_macs:
                mac = fragment_macs.macs[segment_id]
                yield mac.digest()

    def write_macs(self, fragment_count):
        """
        Emit MAC key and a copy of all digests,

        once for each fragment of each segment for each authorized set (i.e.
        for each output produced by encode_segments()).
        """
        mac_headers = {}
        for h in self.headers.values():
            payload = byte_streams.resize_seqs(
                self.mac_slice_size_bytes,
                self.aset_mac_byte_stream(
                    h.aset_id, h.fragment_id, h.segment_count))
            if not hasattr(self, 'mac_slice_count'):
                # Each MAC payload has the same part count. Realize and
                # assign it the first time around.
                payload = list(payload)
                self.mac_slice_count = len(payload)
            for slice_id, chunk in enumerate(payload):
                mac_header = MacHeader(payload_size=len(chunk),
                                       aset_id=h.aset_id,
                                       fragment_id=h.fragment_id,
                                       segment_count=h.segment_count,
                                       fragment_count=fragment_count,
                                       slice_id=slice_id,
                                       slice_count=self.mac_slice_count,
                                       key_size_bytes=self.mac_key_size_bytes,
                                       algorithm=self.mac_algorithm)
                mac_header.metadata.share_id = h.metadata.share_id
                mac_headers[mac_header.to_key()] = mac_header
                self.writer.write(h.metadata.share_id, mac_header, chunk)
        self.headers.update(mac_headers)

    # Entrypoint
    def encode(self, secret_data_segments, m, n):
        self.configure(m, n)
        authorized_sets = crypto.m_of_n_access_structure(m, n)
        # Split data segments into encrypted fragments
        n_segments = self.encode_segments(
            secret_data_segments, authorized_sets)
        if n_segments == 0:
            raise ValueError("Input is empty, no output produced.")

        # Patch FragmentHeaders now that the total number of segments is known.
        # Also mix header bytes into MAC digests.
        self.patch_headers(n_segments)

        # Write MACs once headers are patched.
        self.write_macs(m)

        # Prepare writer for the post_process() step.
        self.n_segments = n_segments
        self.writer.summary(self)

        # Optional post-processing step (headers dict produces values in
        # order).
        for header in self.headers.values():
            self.writer.post_process(header)


class AppendingEncoder(Encoder):
    """
    An AppendingEncoder is an Encoder adjusted to append split, encrypted

    output fragments to a single set of outputs. It produces one set of split,
    encrypted, output fragments for all elements of secret_data_segments
    provided to the encode(secret_data_segments, m, n) method. Each output data
    fragment payload is the same length as the entire input. (Output MAC parts
    are of fixed size).
    """

    def update_mac(self, aset_id, fragment_id, fragment):
        segment_id = 0  # Appending encoder appends to first and only segment
        share_mac = self.macs[aset_id][fragment_id]
        share_mac.macs[segment_id].update(fragment)

    def encode_segments(self, secret_data_segments, authorized_sets):
        secret_data_segments = iter(secret_data_segments)
        try:
            first_segment = next(secret_data_segments)
        except StopIteration:
            # No segments available
            return 0

        n_segments = super().encode_segments([first_segment], authorized_sets)

        segment_id = 0
        for secret_segment in secret_data_segments:
            for aset in authorized_sets:
                aset_id = aset['aset_id']
                for fragment_id, (share_id, fragment) in enumerate(
                        zip(aset['share_ids'],
                            crypto.split_secret(secret_segment, self.m))):
                    header_key = FragmentHeader(
                        aset_id=aset_id,
                        segment_id=segment_id,
                        fragment_id=fragment_id).to_key()
                    header = self.headers[header_key]
                    header.payload_size += len(fragment)
                    self.writer.append(share_id, header, fragment)
                    self.update_mac(aset_id, fragment_id, fragment)

        return n_segments


###############################################################################
# Decoder

class Reader():
    """
    A Decoder uses a Reader to find and consume input.
    """

    def locate_inputs(self):
        """
        Yield a sequence of TaggedInput(header, handle) namedtuples.

        The input_stream is an iterable of byte sequences, and the handle is
        an object that describes the source of the input_stream.
        """
        raise NotImplementedError()

    def payload_stream(self, tagged_input):
        """
        Return byte stream for payload of TAGGED_INPUT.

        I.e. skip the header, then return rest of data as an iterable of byte
        sequences. TAGGED_INPUT is a TaggedInput namedtuple, a pair of (header,
        handle) produced by self.locate_inputs().
        """
        raise NotImplementedError()


class MacWarning(Exception):
    pass


ReferenceMac = namedtuple("ReferenceMac", ["key", "digest", "algorithm"])
TaggedInput = namedtuple("TaggedInput", ["header", "handle"])


def validate_header_attr(tagged_input, attr, expect):
    header, handle = tagged_input
    attr_val = getattr(header, attr)
    if attr_val != expect:
        raise ValueError(
            f"Inconsistent {attr}. Expected {expect} but got {attr_val} "
            f"in header of {handle}: {header}")


class MacLoader:
    """
    MacLoader is a Decoder companion class used to parse and load MACs.

    It finds and indexes MAC keys and digests included with shares of a split
    secret. It uses a reference back to the decoder to locate MAC files and
    write an index of loaded MACs.
    """

    def __init__(self, decoder):
        self.decoder = decoder

        # aset_id -> segment_id -> fragment_id -> ReferenceMac
        decoder.reference_macs = {}

    @staticmethod
    def validate_mac_header(tagged_input, segment_count, fragment_count,
                            slice_count):
        header, handle = tagged_input
        validate_header_attr(tagged_input, 'segment_count', segment_count)
        validate_header_attr(tagged_input, 'fragment_count', fragment_count)
        validate_header_attr(tagged_input, 'slice_count', slice_count)
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

    def concat_mac_slices(self, mac_slices, aset_id, fragment_id):
        # mac_slices is dict: {slice_id: slice}
        slice_count = len(mac_slices)

        def get_slice(slice_id):
            try:
                return mac_slices[slice_id]
            except KeyError as e:
                raise ValueError(
                    f"Missing MAC slice {slice_id+1}/{slice_count} for fragment "
                    f"{fragment_id=} of authorized set {aset_id=}") from e
        header0 = get_slice(0).header
        for slice_id in range(slice_count):
            self.validate_mac_header(get_slice(slice_id),
                                     self.decoder.segment_count,
                                     header0.fragment_count,
                                     slice_count)
        mac_data = b''
        for slice_id in range(slice_count):
            tagged_input = mac_slices[slice_id]
            payload = b''
            for chunk in self.decoder.reader.payload_stream(tagged_input):
                payload += chunk
            n_bytes = len(payload)
            if n_bytes != tagged_input.header.payload_size:
                raise ValueError(
                    f"Expected to decode {tagged_input.header.payload_size} "
                    f"bytes, but got {n_bytes} bytes of MAC data for "
                    f"{fragment_id=} of authorized set {aset_id=}")
            mac_data += payload
        return (header0, mac_data)

    @staticmethod
    def fragment_macs_digest_index(header, data):
        """
        Return ReferenceMac objects and digests provided in DATA as tuple
        of 2 dicts: (own_macs, digests).
          own_macs: segment_id -> ReferenceMac
          digests:  (segment_id, fragment_id) -> digest<bytes>

        DATA is obtained by concatenating payloads of Mac slices, each of which
        has a header. HEADER is a Mac slice header (any one of them will do,
        only need Mac metadata which is replicated in each header). DATA is a
        byte sequence, a Mac key followed by digests for all fragments of all
        segments of an authorized set. The HEADER identifies which fragment
        (thus which share) the key is for. The key is bundled with digests for
        the fragment, and returned in OWN_MACS. All digests (including those in
        OWN_MACS) are returned in DIGESTS.
        """
        data = memoryview(data)
        key = data[0:header.key_size_bytes]
        mac_data = data[header.key_size_bytes:]
        own_macs = {}
        digests = {}
        cursor = 0
        for segment_id in range(header.segment_count):
            for fragment_id in range(header.fragment_count):
                digest_size = crypto.digest_size_bytes(header.algorithm)
                digest = mac_data[cursor:cursor+digest_size]
                if len(digest) != digest_size:
                    raise ValueError(
                        f"Invalid MAC data for {segment_id=}, {fragment_id=}. "
                        f"Expected a digest of {digest_size} bytes, but got "
                        f"{len(digest)} bytes instead.")
                cursor += digest_size
                digests[(segment_id, fragment_id)] = digest
                if fragment_id == header.fragment_id:
                    own_macs[segment_id] = ReferenceMac(
                        bytes(key), bytes(digest), header.algorithm)
        return (own_macs, digests)

    @staticmethod
    def validate_digests_consistent(header, digest_index, digest_index0):
        """
        Every fragment of the aset should include a full, identical copy of the
        MAC digests for all segments of all fragments of the aset.
          DIGEST_INDEX is (segmgent_id, fragment_id) -> bytes.
          DIGEST_INDEX0 is the same shape as DIGEST_INDEX and compared to it.
        """
        for fragment_id in range(header.fragment_count):
            for segment_id in range(header.segment_count):
                digest = digest_index[(segment_id, fragment_id)]
                d0 = digest_index0[(segment_id, fragment_id)]
                if digest != d0:
                    raise ValueError(
                        f"Invalid MAC digest for {segment_id=} of "
                        f"{fragment_id=}. Each share received an identical "
                        "copy of the MAC digests computed for each segment of "
                        "each fragment of the authorized set, but this copy "
                        "of the digest doesn't match the others.")

    def build_mac_index(self, aset_id, aset_macs):
        # aset_macs: [(fragment_id, slice_id -> TaggedInput)]
        # iter[(fragment_id, dict[slice_id, TaggedInput(MacHeader, Path)])]
        aset_macs = iter(aset_macs)

        def get_macs(header, data, aset_id, aset_fragment_id):
            try:
                return self.fragment_macs_digest_index(header, data)
            except Exception as e:
                raise RuntimeError(
                    f"Failed to load MACs from fragment_id={aset_fragment_id} "
                    f"of authorized set {aset_id=} from MAC slices with header:"
                    f" {header}") from e

        mac_index = defaultdict(dict)
        self.decoder.reference_macs[aset_id] = mac_index

        def index_macs(fragment_id, fragment_macs):
            for segment_id, reference_mac in fragment_macs.items():
                mac_index[segment_id][fragment_id] = reference_mac

        # Index MACs for first available fragment
        try:
            (fragment_id0, mac_slices0) = next(aset_macs)
        except StopIteration:
            return mac_index
        (header0, data0) = self.concat_mac_slices(mac_slices0, aset_id, fragment_id0)
        (frag_macs0, digest_index0) = get_macs(header0, data0, aset_id, fragment_id0)
        index_macs(fragment_id0, frag_macs0)

        # Index MACs for remaining fragments
        for fragment_id, mac_slices in aset_macs:
            (header, data) = self.concat_mac_slices(mac_slices, aset_id, fragment_id)
            (frag_macs, digest_index) = get_macs(header, data, aset_id, fragment_id)
            try:
                self.validate_digests_consistent(
                    header, digest_index, digest_index0)
            except Exception as e:
                raise RuntimeError(
                    f"Inconsistent MACs from fragment_id={fragment_id} "
                    f"of authorized set {aset_id=} from MAC slices with header:"
                    f" {header}") from e
            index_macs(fragment_id, frag_macs)
        return mac_index

    @staticmethod
    def ensure_mac_all_fragments(segment_macs, fragment_count):
        """
        Ensure SEGMENT_MACS contains an entry for each fragment.

        SEGMENT_MACS is dict of fragment_id -> ReferenceMac.
        A ReferenceMac is a namedtuple of key, digest, algorithm.
        """
        if len(segment_macs) != fragment_count:
            raise ValueError(
                f"Unexpected number of reference MACs loaded. Expected "
                f"{fragment_count} but got {len(segment_macs)}.")
        for fragment_id in range(fragment_count):
            if fragment_id not in segment_macs:
                raise ValueError(
                    f"Missing MAC for {fragment_id=}.")

    def load_macs(self, aset_id, segment_id):
        """
        Load MACs for segment SEGMENT_ID of fragments in authorized set ASET_ID.

        Return dict of fragment_id -> ReferenceMac.
        A ReferenceMac is a namedtuple of key, digest, algorithm.
        """
        try:
            mac_index = self.decoder.reference_macs[aset_id]
        except KeyError:
            # Could build mac_index in except-block here, but nested errors
            # from build_mac_index become harder to understand.
            mac_index = None
        # So call build_mac_index at top level without a surrounding exception
        # context instead:
        if mac_index is None:
            mac_index = self.build_mac_index(
                aset_id, self.decoder.mac_parts[aset_id].items())
        return mac_index[segment_id]


class Decoder:
    """
    Combine (and thus decrypt) shares of a split secret.

    A Decoder combines shares of a secret produced by an Encoder and recovers
    the original input. It scans available secret share fragments and attempts
    to parse their Headers to discover complete authorized sets that can be
    decoded and concatenated to recover the original input. It also verifies
    integrity of the recovered secret by recomputing and comparing MAC digests
    of the secret shares.
    """

    def __init__(self, reader, *,
                 name=None,
                 fragment_read_size=(4096*16),
                 **_opts):
        self.reader = reader
        self.fragment_read_size = fragment_read_size
        self.name = name or type(self).__name__

    ## Helpers
    def eprint(self, *args):
        eprint(f"{self.name}:", *args)

    ## Implementation
    def print_registered_headers(self, file=sys.stdout):

        def pr(*args):
            print(f"{self.name}:", *args, file=file)

        if hasattr(self, 'frags_by_segment') and self.frags_by_segment:
            pr("Found data fragments:")
            for header, handle in sorted(
                    itertools.chain(*self.frags_by_segment.values()),
                    key=lambda ti: ti.header.to_key()):
                pr(f"{handle}: {header}")
        else:
            pr("No data fragments discovered.")

        if hasattr(self, 'mac_parts') and self.mac_parts:
            pr("Found MAC inputs:")
            for _aset_id, aset_macs in sorted(self.mac_parts.items()):
                for _fragment_id, mac_parts in sorted(aset_macs.items()):
                    for _, (header, handle) in sorted(mac_parts.items()):
                        pr(f"{handle}: {header}")
        else:
            pr("No MACs discovered.")

    def ensure_segment_count(self, tagged_input):
        header, handle = tagged_input
        if not hasattr(self, 'segment_count'):
            if header.segment_count == 0:
                raise ValueError(
                    f"Invalid segment_count=0 in header of {handle}: {header}")
            self.segment_count = header.segment_count
        validate_header_attr((header, handle), 'segment_count',
                             self.segment_count)

    def register_input(self, tagged_input):
        header, handle = tagged_input
        if isinstance(header, FragmentHeader):
            self.frags_by_segment[header.segment_id].append(tagged_input)
            self.ensure_segment_count(tagged_input)
        elif isinstance(header, MacHeader):
            aset_macs = self.mac_parts[header.aset_id]
            fragment_macs = aset_macs[header.fragment_id]
            fragment_macs[header.slice_id] = tagged_input
        else:
            raise ValueError(
                f"Unknown header type {type(header).__name__}.")

    def load(self):
        """
        Scan input directories, find all fragment and MAC files

        parsing their Headers, and add them to indexes.
        """
        # segment_id -> fragment_id -> TaggedInput(FragmentHeader, Path)
        # dict[segment_id, list[TaggedInput(FragmentHeader, Path)]]
        self.frags_by_segment = defaultdict(list)

        # aset_id -> fragment_id -> slice_id -> TaggedInput(MacHeader, Path)
        # dict[aset_id,
        #      dict[fragment_id, dict[slice_id, TaggedInput(MacHeader Path)]]]
        self.mac_parts = defaultdict(lambda: defaultdict(dict))

        # mac_loader is a cooperating companion class that uses
        # self.payload_stream(...), reads self.mac_parts and
        # self.segment_count, and writes self.reference_macs.
        self.mac_loader = MacLoader(self)

        # Register all inputs from all available shares.
        for tagged_input in self.reader.locate_inputs():
            try:
                self.register_input(tagged_input)
            except Exception as e:
                self.eprint(
                    f"Unable to register header in {tagged_input.handle}, "
                    "skipping it. Failed with:")
                print_exception(e)
                continue
        if not self.frags_by_segment or not hasattr(self, 'segment_count'):
            raise RuntimeError("No input found.")

    def segments(self):
        """
        Yield lists of TaggedInputs, one list per segment.

        Each list contains all available fragments of the segment from one or
        more authorized sets. Fragments of a single, complete authorized set
        can be combined to recover the original input segment.
        """
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
        """
        Return True if authorized set ASET is complete.

        ASET is a dictionary keyed by fragment_id, FRAGMENT_COUNT is the number
        of fragments in a complete authorized set. Fragment ids are consecutive
        integers from 0 through fragment_count - 1.
        """
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
        """
        Return sequence of TaggedInputs of a complete authorized set.

        SEGMENT is a collection of TaggedInputs.
        """
        asets = defaultdict(dict)
        if not segment:
            raise ValueError(
                f"Segment {segment_id=} is empty (contains no fragments), so "
                "it's impossible to find an authorized set of fragments to "
                "decrypt it.")
        fragment_count = segment[0].header.fragment_count
        payload_size = segment[0].header.payload_size
        for tagged_input in segment:
            validate_header_attr(tagged_input, 'fragment_count',
                                 fragment_count)
            validate_header_attr(tagged_input, 'payload_size',
                                 payload_size)
            aset = asets[tagged_input.header.aset_id]
            aset[tagged_input.header.fragment_id] = tagged_input
            if self.is_complete_aset(aset, fragment_count):
                return list(aset.values())
        raise RuntimeError(
            f"Unable to find complete authorized set of size {fragment_count} "
            f"for segment {segment_id=}")

    def fragments(self, authorized_set):
        """
        Return iterator over chunks of fragments of AUTHORIZED_SET.

        AUTHORIZED_SET is collection of TaggedInputs.
        """
        input_streams = [
            byte_streams.resize_seqs(
                self.fragment_read_size,
                self.reader.payload_stream(tagged_input))
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

    def combine_fragments(self, authorized_set, segment_id,
                          ignore_mac_error=False):
        """
        Combine fragments of AUTHORIZED_SET for segment SEGMENT_ID.

        Return a generator that yields chunks of reconstructed secret and
        returns True if MACs are valid. AUTHORIZED_SET is a collection of
        TaggedInputs.
        """
        if not authorized_set:
            raise ValueError(
                "Authorized set is empty (contains no fragments), so there "
                "are no fragments to decrypt.")

        macs_valid = True

        def mac_error(msg, cause=None):
            nonlocal macs_valid
            macs_valid = False
            if ignore_mac_error:
                self.eprint(
                    f"WARNING: {msg}" + (f": {cause}" if cause else ""))
            else:
                raise RuntimeError(
                    f"{self.name}: ERROR: Unable to verify authenticity of "
                    "output. Aborting any remaining decoding process. Use "
                    "extreme caution handling any partial output, it "
                    "may have been modified by an attacker.\n"
                    f"Reason: {msg}") from cause

        headers = [tf.header for tf in authorized_set]

        # Each fragment header of the authorized_set has the same aset_id and
        # payload_size, so read the first one.
        aset_id = headers[0].aset_id
        payload_size = headers[0].payload_size
        try:
            reference_macs = self.mac_loader.load_macs(aset_id, segment_id)
            self.mac_loader.ensure_mac_all_fragments(reference_macs,
                                                     len(authorized_set))
        except Exception as e:
            mac_error(
                f"Failed to load MACs while decoding {segment_id=} with "
                f"authorized set {aset_id=}",
                cause=e)
            reference_macs = {}

        n_bytes = 0
        computed_macs = {fragment_id: crypto.new_mac(mac.key, mac.algorithm)
                         for (fragment_id, mac)
                         in reference_macs.items()}
        # Produce sequence of combined outputs, updating MACs along the way.
        for fragment_chunks in self.fragments(authorized_set):
            for (header, frag_chunk) in zip(headers, fragment_chunks):
                if computed_macs:
                    computed_macs[header.fragment_id].update(frag_chunk)
            output_chunk = crypto.combine_fragments(fragment_chunks)
            n_bytes += len(output_chunk)
            yield output_chunk
        # Finally add Header bytes into MACs
        if computed_macs:
            for header in headers:
                computed_macs[header.fragment_id].update(header.to_bytes())
        # Report length mismatch to give better error feedback. This isn't
        # strictly necessary because a bad length will cause the MAC validation
        # to fail, and HMAC is not vulnerable to length extension attack.
        if payload_size != n_bytes:
            raise ValueError(
                f"Expected to decode {payload_size} bytes, but decoded "
                f"{n_bytes} bytes of {segment_id=} of authorized set "
                f"{aset_id=}")
        # Finally validate MACs.
        for fragment_id, reference_mac in reference_macs.items():
            computed_mac = computed_macs[fragment_id]
            if not crypto.digests_equal(reference_mac.digest,
                                        computed_mac.digest()):
                mac_error(
                    f"MAC digest mismatch for {segment_id=} of {fragment_id=} "
                    f"authorized set {aset_id=}")
        return macs_valid

    ## Entrypoint
    def decode(self, ignore_mac_error=False):
        macs_valid = True
        try:
            self.load()
        finally:
            self.print_registered_headers(file=sys.stderr)
        for segment_id, segment in enumerate(self.segments()):
            authorized_set = self.authorized_set(segment_id, segment)
            ret = yield from self.combine_fragments(
                authorized_set, segment_id, ignore_mac_error)
            macs_valid = ret and macs_valid
        if not macs_valid:
            raise MacWarning()


class Reporter():
    """
    The Reporter class supports the "identify" feature.

    It scans, indexes, and authenticates shares of a split secret without
    actually decrypting it, and prints a summary of what it found.
    """

    def __init__(self, decoder):
        self.decoder = decoder

    def identify_segment(self, segment_id, segment):
        """
        Print details about SEGMENT SEGMENT_ID.

        SEGMENT is a collection of TaggedInputs.
        """
        ok = True
        computed_macs = {}
        segment = sorted(segment, key=lambda ti: ti.header.to_key())
        aset_ids = sorted({frag.header.aset_id for frag in segment})
        for aset_id in aset_ids:
            try:
                aset_segment_macs = self.decoder.mac_loader \
                                                .load_macs(aset_id, segment_id)
                computed_macs[aset_id] = {
                    fragment_id: crypto.new_mac(reference_mac.key,
                                                reference_mac.algorithm)
                    for (fragment_id, reference_mac)
                    in aset_segment_macs.items()}
            except Exception as e:
                print(f"Failed to load MACs while decoding {segment_id=} "
                      f"with authorized set {aset_id=}")
                print_exception(e, file=sys.stdout)
                ok = False
        expected_sizes = [tf.header.payload_size for tf in segment]
        payload_sizes = [0] * len(segment)
        # Compute MACs and sizes
        for fragment_chunks in self.decoder.fragments(segment):
            for i, (frag_chunk, tf) in enumerate(zip(fragment_chunks,
                                                     segment)):
                header = tf.header
                payload_sizes[i] += len(frag_chunk)
                try:
                    mac = computed_macs[header.aset_id][header.fragment_id]
                except KeyError:
                    ok = False
                    continue
                mac.update(frag_chunk)
        # Check sizes
        for i, tf in enumerate(segment):
            print(f"Check payload size of {tf.handle} ...", end='')
            esz = expected_sizes[i]
            psz = payload_sizes[i]
            if esz != psz:
                tf = segment[i]
                print(f"\nUnexpected payload size of {psz} bytes, expected "
                      f"{esz} in header of {tf.handle}: {tf.header}")
                ok = False
            else:
                print(f" ok: {psz} bytes as expected")
        # Check MACs
        ref_macs = self.decoder.reference_macs
        for header, handle in segment:
            print(f"Check MAC digest of {handle} ...", end='')
            aset_id = header.aset_id
            fragment_id = header.fragment_id
            try:
                reference_mac = ref_macs[aset_id][segment_id][fragment_id]
            except KeyError:
                print(
                    f" no reference MAC available for {segment_id=} of "
                    f"{fragment_id=} of authorized set {aset_id=}")
                ok = False
                continue
            try:
                computed_mac = computed_macs[aset_id][fragment_id]
            except KeyError:
                print(
                    f" no computed MAC available for {segment_id=} of "
                    f"{fragment_id=} of authorized set {aset_id=}")
                ok = False
                continue
            computed_mac.update(header.to_bytes())
            if crypto.digests_equal(reference_mac.digest, computed_mac.digest()):
                print(" ok")
            else:
                ok = False
                print(
                    f"\nERROR: Unable to verify authenticity of {segment_id=} "
                    f"of {fragment_id=} of authorized set {aset_id=}: "
                    "Computed MAC digest does not match reference MAC digest. "
                    "Use extreme caution handling any decoded output, it may "
                    "have been modified by an attacker.")
        return ok

    ## Entrypoint
    def identify(self):
        ok = True
        try:
            self.decoder.load()
        finally:
            self.decoder.print_registered_headers()
        for segment_id, segment in enumerate(self.decoder.segments()):
            ret = self.identify_segment(segment_id, segment)
            ok = ret and ok
        return ok
