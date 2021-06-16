# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


from __future__ import annotations

import io
import random
from typing import BinaryIO, Optional, Iterable

from Crypto.Random import get_random_bytes

from codn._common import read_or_fail, CLUSTER_SIZE
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

    The format is:

        blob_size: uint16
        blob_data:  bytes (exactly blob_size bytes)
        --
        blob_size: uint16
        blob_data:  bytes (exactly blob_size bytes)
        --
        blob_data:  bytes
        eof

    So the last blob does NOT have the size header and just ends at the end
    of file.
    """

    def __init__(self, target_io: BinaryIO):
        self.target_io = target_io
        self._closed = False
        self._next_blob: Optional[bytes] = None
        self._tail_written = False

    def close(self):
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # def __del__(self):
    #     if not self._closed:
    #         raise RuntimeError("close() method was not called")
    # print('Destructor called, Employee deleted.')

    def write_bytes(self, buffer: bytes):
        if self._tail_written:
            raise RuntimeError("Cannot run this after tail written")
        if len(buffer) != CLUSTER_SIZE:
            raise ValueError("Unexpected length")


        # checksum = zlib.crc32(buffer)
        # self.target_io.write(uint32_to_bytes(checksum))
        #
        # size_obfuscated = (len(buffer) ^ checksum) & 0xFFFF
        # self.target_io.write(uint16_to_bytes(len(buffer)))
        self.target_io.write(buffer)

    def write_io(self, source_io: BinaryIO, size: int):
        # todo chunks
        buffer = read_or_fail(source_io, size)
        self.write_bytes(buffer)

    def write_tail(self):
        if self._tail_written:
            raise RuntimeError("Cannot run this after tail written")

        tail = get_random_bytes(random.randint(1, CLUSTER_SIZE - 1))
        assert 1 <= len(tail) < CLUSTER_SIZE
        self.target_io.write(tail)
        self._tail_written = True



# class BlobsSequentialReader:
#     """Iterates BLOBs sequentially from a stream created by BlobsWriter.
#     Reading data is optional: the read_io method only returns FragmentReaderIO
#     objects that know about the position of the BLOB in the original stream.
#     """
#
#     def __init__(self, source_io: BinaryIO):
#         self.source_io = source_io
#         self._next_blob_pos: Optional[int] = None
#
#         pos = source_io.tell()
#         self._source_size = source_io.seek(0, io.SEEK_END)
#         source_io.seek(pos, io.SEEK_END)
#
#     def read_io(self) -> Optional[FragmentIO]:
#
#         if self._next_blob_pos is not None:
#             self.source_io.seek(self._next_blob_pos, io.SEEK_SET)
#
#         # part_length_bytes = self.source_io.read(2)
#         # if len(part_length_bytes) == 0:
#         #     return None
#         # if len(part_length_bytes) != 2:
#         #     raise InsufficientData(f'bytes read: {len(part_length_bytes)}')
#
#         # part_length = bytes_to_uint16(part_length_bytes)
#
#         # part_checksum_bytes = self.source_io.read(4)
#         # if len(part_checksum_bytes) == 0:
#         #     return None
#         # if len(part_checksum_bytes) != 4:
#         #     raise InsufficientData(f'bytes read: {len(part_checksum_bytes)}')
#
#         # part_checksum = bytes_to_uint32(part_checksum_bytes)
#         # part_length_obfuscated = bytes_to_uint16(
#         #     read_or_fail(self.source_io, 2))
#         # part_length = (part_length_obfuscated ^ part_checksum) & 0xFFFF
#
#         outer_stream_pos = self.source_io.seek(0, io.SEEK_CUR)
#         self._next_blob_pos = outer_stream_pos + CLUSTER_SIZE
#
#
#         return FragmentIO(self.source_io,
#                           outer_stream_pos,
#                           part_length)
#
#     def read_bytes(self) -> Optional[bytes]:
#         t = self.read_io()
#         if t is None:
#             return None
#         sub_io = t
#         sub_io.seek(0, io.SEEK_SET)
#         result = sub_io.read()
#
#         return result


class BlobsIndexedReader:
    """Scans the complete list of BLOBs in the stream and lets you access
    them in random order.
    BLOB data is not read, checksums are not verified.
    The blobs are just converted to FragmentIO and stored to the list.
    """

    def __init__(self, source_io: BinaryIO, close_stream=False):

        self.source_io = source_io
        self.close_stream = close_stream

        # The blobs list must start at the current stream position.
        # But not necessarily from the beginning of the stream.

        # self._items: List[FragmentIO] = []


        self._start_pos = self.source_io.tell()
        self._io_size = self.source_io.seek(0, io.SEEK_END)
        self._len = (self._io_size - self._start_pos)//CLUSTER_SIZE
        self.source_io.seek(self._start_pos, io.SEEK_SET)

        # if source_io is not None:
        #     br = BlobsSequentialReader(source_io)
        #     while True:
        #         tpl = br.read_io()
        #         if tpl is None:
        #             break
        #         self._items.append(tpl)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.close_stream:
            self.source_io.close()

    def __len__(self):
        return self._len
        # d = self._io_size - self._start_pos
        # assert d % CLUSTER_SIZE == 0
        # return d // CLUSTER_SIZE

    @property
    def tail_size(self):
        return (self._io_size - self._start_pos) - len(self)*CLUSTER_SIZE

    def io(self, idx: int) -> FragmentIO:

        if idx < 0:
            raise IndexError("Negative value")
        if idx >= len(self):
            raise IndexError(f"Must not be larger than {len(self)}")

        # frio = self._items[idx]

        # we will not actually actually use the fragment io, but return
        # its copy

        #assert self.source_io is not None
        return FragmentIO(self.source_io,
                          self._start_pos + idx * CLUSTER_SIZE,
                          CLUSTER_SIZE)

        # frio.seek(0, io.SEEK_SET)
        # return frio

    # def get_bytes(self, idx: ):

    def __iter__(self) -> Iterable[FragmentIO]:
        for i in range(len(self)):
            yield self.io(i)
