# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


from __future__ import annotations

import io
import random
from typing import BinaryIO, Optional, Iterable

from Crypto.Random import get_random_bytes

from dmk._common import read_or_fail, CLUSTER_SIZE
from dmk.b_storage_file._10_fragment_io import FragmentIO


class BlocksSequentialWriter:

    def __init__(self, target_io: BinaryIO):
        self.target_io = target_io
        self._next_blob: Optional[bytes] = None
        self._tail_written = False

    def __enter__(self):
        # todo remove
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def write_bytes(self, buffer: bytes):
        if self._tail_written:
            raise RuntimeError("Cannot run this after tail written")
        if len(buffer) != CLUSTER_SIZE:
            raise ValueError("Unexpected length")

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


class BlocksIndexedReader:

    def __init__(self, source_io: BinaryIO, close_stream=False):

        self.source_io = source_io
        self.close_stream = close_stream

        # The blobs list must start at the current stream position.
        # But not necessarily from the beginning of the stream.

        self._start_pos = self.source_io.tell()
        self._io_size = self.source_io.seek(0, io.SEEK_END)
        self._len = (self._io_size - self._start_pos) // CLUSTER_SIZE
        self.source_io.seek(self._start_pos, io.SEEK_SET)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.close_stream:
            self.source_io.close()

    def __len__(self):
        return self._len

    @property
    def tail_size(self):
        return (self._io_size - self._start_pos) - len(self) * CLUSTER_SIZE

    def io(self, idx: int) -> FragmentIO:

        if idx < 0:
            raise IndexError("Negative value")
        if idx >= len(self):
            raise IndexError(f"Must not be larger than {len(self)}")

        return FragmentIO(self.source_io,
                          self._start_pos + idx * CLUSTER_SIZE,
                          CLUSTER_SIZE)

    def __iter__(self) -> Iterable[FragmentIO]:
        for i in range(len(self)):
            yield self.io(i)
