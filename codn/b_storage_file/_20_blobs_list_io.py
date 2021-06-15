# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


from __future__ import annotations

import io
import zlib
from typing import BinaryIO, Tuple, Optional, List, Iterable

from codn._common import read_or_fail, InsufficientData
from codn.b_cryptoblobs._10_byte_funcs import uint32_to_bytes, \
    bytes_to_uint32, uint16_to_bytes, bytes_to_uint16
from codn.b_storage_file._10_fragment_io import FragmentIO


def _obfuscate_size(size16: int, crc32: int) -> int:
    if not 0 <= size16 <= 0xFFFF:
        raise ValueError(f"size: {size16}")
    if not 0 <= crc32 <= 0xFFFFFFFF:
        raise ValueError(f"crc32: {crc32}")

    mix_mask = (crc32 >> 16) ^ crc32
    return (size16 ^ mix_mask) & 0xFFFF


class BlobsSequentialWriter:
    """Writes BLOBs sequentially to a binary stream.
    Each BLOB record is just:
        blob_size:  uint32
        blob_crc32: uint32
        blob_data:  bytes (exactly blob_size bytes)
    """

    def __init__(self, target_io: BinaryIO):
        self.target_io = target_io

    def write_bytes(self, buffer: bytes):
        if len(buffer) > 0xFFFF:
            raise ValueError(f"Too large: {len(buffer)}")

        checksum = zlib.crc32(buffer)
        self.target_io.write(uint32_to_bytes(checksum))

        size_obfuscated = (len(buffer) ^ checksum) & 0xFFFF
        self.target_io.write(uint16_to_bytes(size_obfuscated))
        self.target_io.write(buffer)

    def write_io(self, source_io: BinaryIO, size: int):
        # todo chunks
        buffer = read_or_fail(source_io, size)
        self.write_bytes(buffer)


class BlobChecksumMismatch(Exception):
    pass


class BlobsSequentialReader:
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

        part_checksum_bytes = self.source_io.read(4)
        if len(part_checksum_bytes) == 0:
            return None
        if len(part_checksum_bytes) != 4:
            raise InsufficientData(f'bytes read: {len(part_checksum_bytes)}')

        part_checksum = bytes_to_uint32(part_checksum_bytes)
        part_length_obfuscated = bytes_to_uint16(
            read_or_fail(self.source_io, 2))
        part_length = (part_length_obfuscated ^ part_checksum) & 0xFFFF

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
    The blobs are just converted to FragmentIO and stored to the list.
    """

    def __init__(self, source_io: Optional[BinaryIO], close_stream=False):

        self.source_io = source_io
        self.close_stream = close_stream

        # The blobs list must start at the current stream position.
        # But not necessarily from the beginning of the stream.

        self._items: List[Tuple[FragmentIO, int]] = []

        if source_io is not None:
            br = BlobsSequentialReader(source_io)
            while True:
                tpl = br.read_io()
                if tpl is None:
                    break
                self._items.append(tpl)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.close_stream:
            self.source_io.close()

    def io(self, idx: int) -> FragmentIO:
        frio, crc = self._items[idx]

        # we will not actually actually use the fragment io, but return
        # its copy

        return FragmentIO(frio.underlying, frio.start, frio.length)

        # frio.seek(0, io.SEEK_SET)
        # return frio

    # def get_bytes(self, idx: ):

    def crc(self, idx: int) -> int:
        frio, crc = self._items[idx]
        return crc

    def check_all_checksums(self):
        for frio, crc in self._items:
            frio.seek(0, io.SEEK_SET)
            if zlib.crc32(frio.read()) != crc:
                raise ValueError("CRC mismatch")

    def __iter__(self) -> Iterable[FragmentIO]:
        for frio, _ in self._items:
            yield FragmentIO(frio.underlying, frio.start, frio.length)

    def __len__(self):
        return len(self._items)
