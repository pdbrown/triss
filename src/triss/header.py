# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import itertools
from types import SimpleNamespace

from triss import byte_streams
from triss import crypto


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


class StrField(BytesField):
    default = ""

    def parse(self, data):
        return super().parse(data).decode('utf-8').rstrip("\0")

    def generate(self, s):
        return super().generate(s.encode('utf-8'))


class Header:
    """
    Abstract Header class.

    Subclasses define __fields__ and __key_fields__ class attributes.
    """

    def __init__(self, **info):
        """
        Construct Header given INFO kwargs.

        INFO holds header data as typed objects (not just byte arrays), and is
        keyed by field names. Retrieve header bytes with get_bytes or to_bytes.
        """
        self.metadata = SimpleNamespace()
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

    def to_key(self):
        return tuple(getattr(self, k) for k in self.__key_fields__)

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
    __key_fields__ = ["tag", "aset_id", "segment_id", "fragment_id"]


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
        IntField("slice_id", 4),
        IntField("slice_count", 4),
        IntField("key_size_bytes", 4),
        StrField("algorithm", 24))
    __key_fields__ = ["tag", "aset_id", "fragment_id", "slice_id"]
