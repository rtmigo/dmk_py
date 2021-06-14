from __future__ import annotations

import io
import zlib
from typing import BinaryIO, Tuple, Optional, List

from codn._common import read_or_fail, InsufficientData
from codn.container._fragment_io import FragmentIO
from codn.cryptodir.namegroup.encdec._20_byte_funcs import uint32_to_bytes, \
    bytes_to_uint32


class BlobsWriter:
    """Writes BLOBs sequentially to a binary stream.

    Each BLOB record is just:
        blob_size:  uint32
        blob_crc32: uint32
        blob_data:  bytes (exactly blob_size bytes)
    """

    def __init__(self, target_io: BinaryIO):
        self.target_io = target_io

    def write_bytes(self, buffer: bytes):
        self.target_io.write(uint32_to_bytes(len(buffer)))
        self.target_io.write(uint32_to_bytes(zlib.crc32(buffer)))
        self.target_io.write(buffer)

    def write_io(self, source_io: BinaryIO, size: int):
        # todo chunks
        buffer = read_or_fail(source_io, size)
        self.write_bytes(buffer)


class BlobChecksumMismatch(Exception):
    pass


class BlobsReader:
    """Iterates BLOBs sequentially from a stream created by BlobsWriter.

    Reading data is optional: the read_io method only returns FragmentReaderIO
    objects that know about the position of the BLOB in the original stream.
    """

    def __init__(self, source_io: BinaryIO):
        self.source_io = source_io
        self._next_blob_pos: Optional[int] = None

    def read_io(self) -> Optional[Tuple[FragmentIO, int]]:

        if self._next_blob_pos is not None:
            self.source_io.seek(self._next_blob_pos, io.SEEK_SET)

        part_length_bytes = self.source_io.read(4)
        if len(part_length_bytes) == 0:
            return None
        if len(part_length_bytes) != 4:
            raise InsufficientData(f'bytes read: {len(part_length_bytes)}')

        part_length = bytes_to_uint32(part_length_bytes)
        part_checksum = bytes_to_uint32(read_or_fail(self.source_io, 4))

        outer_stream_pos = self.source_io.seek(0, io.SEEK_CUR)
        self._next_blob_pos = outer_stream_pos + part_length

        return FragmentIO(self.source_io,
                          outer_stream_pos,
                          part_length), \
               part_checksum

    def read_bytes(self) -> Optional[bytes]:
        t = self.read_io()
        if t is None:
            return None
        sub_io, crc = t
        sub_io.seek(0, io.SEEK_SET)
        result = sub_io.read()

        if zlib.crc32(result) != crc:
            raise BlobChecksumMismatch

        return result


class BlobsIndexedReader:
    """Scans the complete list of BLOBs in the stream and lets you access
    them in random order.

    BLOB data is not read, checksums are not verified.

    """

    def __init__(self, source_io: BinaryIO):

        # The blobs list must start at the current stream position.
        # But not necessarily from the beginning of the stream.

        br = BlobsReader(source_io)
        self._items: List[Tuple[FragmentIO, int]] = []
        while True:
            tpl = br.read_io()
            if tpl is None:
                break
            self._items.append(tpl)

    def io(self, idx: int) -> FragmentIO:
        frio, crc = self._items[idx]
        frio.seek(0, io.SEEK_SET)
        return frio

    def crc(self, idx: int) -> int:
        frio, crc = self._items[idx]
        return crc

    def check_all_checksums(self):
        for frio, crc in self._items:
            frio.seek(0, io.SEEK_SET)
            if zlib.crc32(frio.read()) != crc:
                raise ValueError("CRC mismatch")

    def __len__(self):
        return len(self._items)
