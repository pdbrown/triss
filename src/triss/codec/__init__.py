# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from enum import IntEnum
import itertools
from collections import defaultdict, namedtuple
import sys

from triss import byte_streams
from triss import crypto
from triss.header import Header, FragmentHeader, MacHeader
from triss.util import eprint, print_exception, verbose



###############################################################################
# Encoder


KeyedMacs = namedtuple("KeyedMacs", ["key", "macs"])

class Encoder:
    """
    Encoder abstract base class.

    An Encoder converts plaintext to split, encrypted shares via M-of-N
    trivial secret sharing with authentication.

    Subclasses must override at least encode_segments().
    """

    DEFAULT_MAC_ALGORITHM = "hmac-sha384"

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
        # aset_id -> fragment_id -> KeyedMacs(frag_key, segment_id -> hmac)
        # list[list[KeyedMacs(key, list[hmac])]]
        self.macs = [[KeyedMacs(crypto.new_mac_key(mac_algorithm), [])
                      for _fragment_id
                      in range(m)]
                     for _aset_id
                     in range(self.n_asets)]
        self.mac_key_size_bytes = len(self.macs[0][0].key)

    def encode_segments(self, secret_data_segments, m, n, authorized_sets):
        """
        Split secret into shares.

        Take an iterator over SECRET_DATA_SEGMENTS (byte sequences), split them
        into shares according to the AUTHORIZED_SETS determined by values of M
        and N which specify an M-of-N secret sharing scheme. See also
        triss.crypto.
        """
        raise NotImplementedError()

    def summary(self, n_segments):
        """
        Called after encode_segments(), at which point total number of
        segments is known.
        """
        self.n_segments = n_segments

    def patch_header(self, share_id, header_key, n_segments):
        """
        Called after summary(), once for each fragment.

        Allows implementing class to patch (update) headers with n_segments.
        SHARE_ID and HEADER_KEY uniquely identify a fragment. HEADER_KEY is an
        object with aset_id, fragment_id, and segment_id properties.
        """
        pass

    def write_macs(self, share_id, header, mac_data_stream):
        """
        Called after all headers are patched, once for each MAC output.

        Allows implementing class to emit MACs. MAC_DATA_STREAM is an iterator
        over byte sequences.
        """
        pass

    def aset_mac_byte_stream(self, aset_id, fragment_id, n_segments):
        """
        Return generator that yields byte sequences of MAC data

        for all fragments of all segments of authorized set aset_id, and
        includes the MAC key for fragment fragment_id.
        """
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
        # Split data segments into encrypted fragments
        n_segments = self.encode_segments(
            secret_data_segments, m, n, authorized_sets)
        if n_segments == 0:
            return
        self.summary(n_segments)
        # Patch FragmentHeaders now that the total number of segments is known.
        # Also add header bytes into MACed data.
        for segment_id in range(n_segments):
            for aset in authorized_sets:
                aset_id = aset['aset_id']
                for fragment_id, share_id in enumerate(aset['share_ids']):
                    fragment_macs = self.macs[aset_id][fragment_id]
                    header = self.patch_header(
                        share_id,
                        FragmentHeader(aset_id=aset_id,
                                       fragment_id=fragment_id,
                                       segment_id=segment_id),
                        n_segments)
                    if header is not None:
                        try:
                            mac = fragment_macs.macs[segment_id]
                        except KeyError:
                            mac = None
                        if mac:
                            mac.update(header.to_bytes())

        # Finally write MACs after all headers are patched.
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


class MappingEncoder(Encoder):
    """
    A MappingEncoder produces a set of split, encrypted outputs for each
    input segment.

    Subclasses must override at least write().
    """

    def write(self, share_id, header, fragment):
        """
        Write a FRAGMENT with HEADER to share SHARE_ID.
        """
        raise NotImplementedError()

    def add_mac(self, aset_id, fragment_id, fragment):
        fragment_macs = self.macs[aset_id][fragment_id]
        mac = crypto.new_mac(fragment_macs.key, self.mac_algorithm)
        mac.update(fragment)
        fragment_macs.macs.append(mac)

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
    """
    An AppendingEncoder produces one set of split, encrypted outputs

    to which fragments, of all split input segments after the first, are
    appended. This class defers most of its work to a MappingEncoder it owns,
    but adds append-specific features.

    Subclasses must override at least append() and patch_append_size().
    """

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
        """
        Append FRAGMENT byte sequence to the output identified by SHARE_ID,
        ASET_ID, and FRAGMENT_ID.
        """
        raise NotImplementedError()

    def patch_append_size(self, share_id, header_key, appended_byte_count):
        """
        Called after summary(), once for each fragment within
        patch_append_header().

        Allows implementing class to patch (update) headers to include a total
        byte count: the headers original payload_size plus the
        APPENDED_BYTE_COUNT. SHARE_ID and HEADER_KEY uniquely identify a
        fragment. HEADER_KEY is an object with aset_id, fragment_id, and
        segment_id properties.
        """
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
        return self.mapping_encoder.patch_header(
            share_id, header_key, n_segments)



###############################################################################
# Decoder

class MacWarning(Exception):
    pass

ReferenceMac = namedtuple("ReferenceMac", ["key", "digest", "algorithm"])
TaggedInput = namedtuple("TaggedInput", ["header", "handle"])


def frag_header_keyfn(tagged_input):
    h = tagged_input.header
    return (h.aset_id, h.segment_id, h.fragment_id)


def validate_header_attr(tagged_input, attr, expect):
    header, handle = tagged_input
    attr_val = getattr(header, attr)
    if attr_val != expect:
        raise ValueError(
            f"Inconsistent {attr}. Expected {expect} but got {attr_val} "
            f"in header of {handle}: {header}")


class Decoder:
    """
    Decoder abstract base class.

    A Decoder combines shares of a secret produced by an Encoder and recovers
    the original input. It scans available secret share fragments and attempts
    to parse their Headers to discover complete authorized sets that can be
    decoded and concatenated to recover the original input.

    Subclasses must override at least input_streams() and payload_stream().
    """

    def __init__(self, *, fragment_read_size=(4096*16)):
        self.fragment_read_size = fragment_read_size
        self.name = type(self).__name__

    def input_streams(self):
        """
        Return iterator over (handle, input_stream) pairs.

        The input_stream is an iterator over byte sequences, and the handle is
        an object that describes the source of the input_stream.
        """
        raise NotImplementedError()

    def payload_stream(self, tagged_input):
        """
        Return iterator over byte sequences of payload of TAGGED_INPUT.

        I.e. skip the header, then return rest of data. TAGGED_INPUT is a
        TaggedInput namedtuple, a pair of (header, handle).
        """
        raise NotImplementedError()

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
                    key=frag_header_keyfn):
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

    def ensure_segment_count(self, header, handle):
        if not hasattr(self, 'segment_count'):
            if header.segment_count == 0:
                raise ValueError(
                    f"Invalid segment_count=0 in header of {handle}: {header}")
            self.segment_count = header.segment_count
        validate_header_attr((header, handle), 'segment_count',
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
        # segment_id -> fragment_id -> TaggedInput(FragmentHeader, Path)
        # dict[segment_id, list[TaggedInput(FragmentHeader, Path)]]
        self.frags_by_segment = defaultdict(list)

        # aset_id -> fragment_id -> part_id -> TaggedInput(MacHeader, Path)
        # dict[aset_id,
        #      dict[fragment_id, dict[part_id, TaggedInput(MacHeader Path)]]]
        self.mac_parts = defaultdict(lambda: defaultdict(dict))

        # mac_loader is a helper class that uses self.payload_stream(...) and
        # reads self.mac_parts and self.segment_count.
        self.mac_loader = MacLoader(self)

        # Register all inputs from all available shares.
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
        """Return sequence of TaggedInputs of an authorized set."""
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
        """Return iterator over chunks of fragments of AUTHORIZED_SET.

        AUTHORIZED_SET is collection of TaggedInputs."""
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

        # Each fragment header in authorized_set has the same aset_id and
        # payload_size, so read the first one.
        aset_id = headers[0].aset_id
        payload_size = headers[0].payload_size
        try:
            reference_macs = self.mac_loader.load_macs(aset_id, segment_id)
            self.mac_loader.ensure_mac_all_fragments(reference_macs,
                                                     len(authorized_set))
        except Exception as e:
            mac_error(
                f"Failed to load MACs while decoding segment {segment_id=} "
                f"with authorized set {aset_id=}",
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


    ### Indentify implementation

    def identify_segment(self, segment_id, segment):
        """
        Print details about SEGMENT SEGMENT_ID.

        SEGMENT is a collection of TaggedInputs.
        """
        ok = True
        computed_macs = {}
        aset_ids = sorted({frag.header.aset_id for frag in segment})
        for aset_id in aset_ids:
            try:
                aset_segment_macs = self.mac_loader.load_macs(aset_id,
                                                              segment_id)
                computed_macs[aset_id] = {
                    fragment_id: crypto.new_mac(reference_mac.key,
                                                reference_mac.algorithm)
                    for (fragment_id, reference_mac)
                    in aset_segment_macs.items()}
            except Exception as e:
                print("Failed to load MACs while decoding segment "
                      f"{segment_id=} with authorized set {aset_id=}")
                print_exception(e, file=sys.stdout)
                ok = False
        expected_sizes = [tf.header.payload_size for tf in segment]
        payload_sizes = [0] * len(segment)
        # Compute MACs and sizes
        for fragment_chunks in self.fragments(segment):
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
        ref_macs = self.mac_loader.reference_macs
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
            self.load()
        finally:
            self.print_registered_headers()
        for segment_id, segment in enumerate(self.segments()):
            ret = self.identify_segment(segment_id, segment)
            ok = ret and ok
        return ok



class MacLoader:
    """
    A MacLoader is a helper used by a Decoder to parse and load MAC keys
    and digests included with shares of a split secret. It uses a reference to
    the decoder to locate MAC files and makes an index of loaded reference_macs
    available to the decoder.
    """

    def __init__(self, decoder):
        self.decoder = decoder

        # aset_id -> segment_id -> fragment_id -> ReferenceMac
        self.reference_macs = {}

    @staticmethod
    def validate_mac_header(tagged_input, segment_count, fragment_count,
                            part_count):
        header, handle = tagged_input
        validate_header_attr(tagged_input, 'segment_count', segment_count)
        validate_header_attr(tagged_input, 'fragment_count', fragment_count)
        validate_header_attr(tagged_input, 'part_count', part_count)
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

    def concat_mac_parts(self, mac_parts, aset_id, fragment_id):
        # mac_parts is dict: {part_id: part}
        part_count = len(mac_parts)
        def get_part(part_id):
            try:
                return mac_parts[part_id]
            except KeyError as e:
                raise ValueError(
                    f"Missing MAC part {part_id+1}/{part_count} for fragment "
                    f"{fragment_id=} of authorized set {aset_id=}") from e
        header0 = get_part(0).header
        for part_id in range(part_count):
            self.validate_mac_header(get_part(part_id),
                                     self.decoder.segment_count,
                                     header0.fragment_count,
                                     part_count)
        payload = b''
        for part_id in range(part_count):
            tagged_input = mac_parts[part_id]
            for chunk in self.decoder.payload_stream(tagged_input):
                payload += chunk
        return (header0, payload)

    @staticmethod
    def fragment_macs_digest_index(header, data):
        """
        Return ReferenceMac objects and digests provided in DATA as tuple
        of 2 dicts: (own_macs, digests).
          own_macs: segment_id -> ReferenceMac
          digests:  (segment_id, fragment_id) -> digest<bytes>

        DATA is obtained by concatenating payloads of Mac parts, each of which
        has a header. HEADER is one of these Mac part headers (any one of them
        will do, only need Mac metadata which is replicated in each header).
        DATA is a byte sequence, a Mac key followed by digests for all
        fragments of all segments of an authorized set. The HEADER identifies
        which fragment (thus which share) the key is for. The key is bundled
        with digests for the fragment, and returned in OWN_MACS. All digests
        (including those in OWN_MACS) are returned in DIGESTS.
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
        # aset_macs: fragment_id -> part_id -> TaggedInput
        # iter[(fragment_id, dict[part_id, TaggedInput(MacHeader Path)])]
        aset_macs = iter(aset_macs)
        def get_macs(header, data, aset_id, aset_fragment_id):
            try:
                return self.fragment_macs_digest_index(header, data)
            except Exception as e:
                raise RuntimeError(
                    f"Failed to load MACs from fragment_id={aset_fragment_id} "
                    f"of authorized set {aset_id=} from MAC parts with header:"
                    f" {header}") from e

        mac_index = defaultdict(dict)
        self.reference_macs[aset_id] = mac_index
        def index_macs(fragment_id, fragment_macs):
            for segment_id, reference_mac in fragment_macs.items():
                mac_index[segment_id][fragment_id] = reference_mac

        # Index MACs for first available fragment
        try:
            (fragment_id0, mac_parts0) = next(aset_macs)
        except StopIteration:
            return
        (header0, data0) = self.concat_mac_parts(mac_parts0, aset_id, fragment_id0)
        (frag_macs0, digest_index0) = get_macs(header0, data0, aset_id, fragment_id0)
        index_macs(fragment_id0, frag_macs0)

        # Index MACs for remaining fragments
        for fragment_id, mac_parts in aset_macs:
            (header, data) = self.concat_mac_parts(mac_parts, aset_id, fragment_id)
            (frag_macs, digest_index) = get_macs(header, data, aset_id, fragment_id)
            try:
                self.validate_digests_consistent(
                    header, digest_index, digest_index0)
            except Exception as e:
                raise RuntimeError(
                    f"Inconsistent MACs from fragment_id={fragment_id} "
                    f"of authorized set {aset_id=} from MAC parts with header:"
                    f" {header}") from e
            index_macs(fragment_id, frag_macs)
        return mac_index

    @staticmethod
    def ensure_mac_all_fragments(segment_macs, fragment_count):
        """
        Ensure SEGMENT_MACS contains an entry for each fragment.

        SEGMENT_MACS is dict of fragment_id -> ReferenceMac
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
            mac_index = self.reference_macs[aset_id]
        except KeyError:
            # Could build mac_index in except: block here, but nested errors
            # from build_mac_index become harder to understand.
            mac_index = None
        # So call build_mac_index at top level without a surrounding exception
        # context instead:
        if mac_index is None:
            mac_index = self.build_mac_index(
                aset_id, self.decoder.mac_parts[aset_id].items())
        return mac_index[segment_id]
