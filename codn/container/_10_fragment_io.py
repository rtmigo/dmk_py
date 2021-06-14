# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import io
#from abc import ABC
from types import TracebackType
from typing import BinaryIO, Optional, Type, Iterator, AnyStr, Iterable


class FragmentIO(BinaryIO):
    """Reads data from a fragment of a stream. The fragment is described
    by start position and the length in bytes.

    The fragment will look like a stream. But this object will only allow
    reading the bytes that belong to the fragment. The seek method will also
    only set the position within the fragment.
    """

    def __exit__(self, t: Optional[Type[BaseException]],
                 value: Optional[BaseException],
                 traceback: Optional[TracebackType]) -> Optional[bool]:
        pass

    def __init__(self, outer: BinaryIO, start: int, length: int):
        super().__init__()
        self.outer = outer
        self.inner_pos = 0  # local position
        self.outer_start = start  # location of substream in the outer stream
        self.length = length
        self._seeked = False

    # @property
    # def inner_pos(self) -> int:
    #     return self._inner_pos
    #
    # @inner_pos.setter
    # def inner_pos(self, x):
    #     return self._inner_pos

    @property
    def _remaining_bytes(self):
        result = self.length - self.inner_pos
        assert 0 <= result <= self.length
        return result

    def _seek_from_start(self, offset: int):
        offset = max(offset, 0)
        offset = min(offset, self.length)
        self.outer.seek(self.outer_start + offset, io.SEEK_SET)
        self.inner_pos = offset
        assert 0 <= self.inner_pos <= self.length

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        self._seeked = True
        if whence == io.SEEK_SET:
            if offset < 0:
                raise ValueError(f"negative seek value {offset}")
            self._seek_from_start(offset)
            return offset
        elif whence == io.SEEK_END:
            new_pos = max(0, self.length + offset)
            self._seek_from_start(new_pos)
            return self.inner_pos
        else:
            raise NotImplementedError(f"Not implemented for whence={whence}")

    def read(self, size: int = -1) -> bytes:

        if size < 0:
            size = self._remaining_bytes
        bytes_to_read = min(self._remaining_bytes, size)
        assert bytes_to_read >= 0
        if bytes_to_read == 0:
            return b''

        # in case the position in the outer stream has been changed
        self._seek_from_start(self.inner_pos)

        buffer = self.outer.read(bytes_to_read)
        self.inner_pos += len(buffer)
        assert 0 <= self.inner_pos <= self.length
        return buffer

    def __enter__(self) -> BinaryIO:
        return self

    def close(self) -> None:
        pass

    def fileno(self) -> int:
        raise NotImplementedError

    def flush(self) -> None:
        raise NotImplementedError

    def isatty(self) -> bool:
        raise NotImplementedError

    def readable(self) -> bool:
        raise NotImplementedError

    def readline(self, limit: int = ...) -> AnyStr:
        raise NotImplementedError

    def readlines(self, hint: int = ...) -> list[AnyStr]:
        raise NotImplementedError

    def seekable(self) -> bool:
        raise NotImplementedError

    def tell(self) -> int:
        raise NotImplementedError

    def truncate(self, size: Optional[int] = ...) -> int:
        raise NotImplementedError

    def writable(self) -> bool:
        raise NotImplementedError

    def write(self, s: AnyStr) -> int:
        raise NotImplementedError

    def writelines(self, lines: Iterable[AnyStr]) -> None:
        raise NotImplementedError

    def __next__(self) -> AnyStr:
        raise NotImplementedError

    def __iter__(self) -> Iterator[AnyStr]:
        raise NotImplementedError
