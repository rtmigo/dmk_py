# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import io
# from abc import ABC
from types import TracebackType
from typing import BinaryIO, Optional, Type, Iterator, AnyStr, Iterable, List


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
        self.__pos = 0  # local position
        self.__start = start  # location of substream in the outer stream
        self.__length = length

    @property
    def start(self) -> int:
        return self.__start

    @property
    def length(self) -> int:
        return self.__length

    # @property
    # def inner_pos(self) -> int:
    #     return self._inner_pos
    #
    # @inner_pos.setter
    # def inner_pos(self, x):
    #     return self._inner_pos

    @property
    def _remaining_bytes(self):
        result = self.length - self.__pos
        assert 0 <= result <= self.length
        return result

    def _seek_to_pos(self):
        self.__pos = max(self.__pos, 0)
        self.__pos = min(self.__pos, self.length)
        assert 0 <= self.__pos <= self.length
        self.outer.seek(self.start + self.__pos, io.SEEK_SET)

    def _bounded_pos(self, position: int) -> int:
        position = max(position, 0)
        position = min(position, self.length)
        assert 0 <= position <= self.length
        return position

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:

        if whence == io.SEEK_SET:
            if offset < 0:
                raise ValueError(f"negative seek value {offset}")
            # self._seek_from_start(offset)
            self.__pos = self._bounded_pos(offset)

            # it's strange, but even if offset is set past the end
            # of the stream, BytesIO returns the offset, not the truncated
            # position inside the stream
            return offset
        elif whence == io.SEEK_END:
            self.__pos = self._bounded_pos(max(0, self.length + offset))
            # todo max unnecessary?
            # self._seek_from_start(new_pos)
            return self.__pos

        elif whence == io.SEEK_CUR:
            if offset == 0:
                return self.__pos
            else:
                raise NotImplementedError(
                    f"Not implemented offset!=0 with whence={whence}")
        else:
            raise ValueError(whence)

    def read(self, size: int = -1) -> bytes:

        if size < 0:
            size = self._remaining_bytes
        bytes_to_read = min(self._remaining_bytes, size)
        assert bytes_to_read >= 0
        if bytes_to_read == 0:
            return b''

        # in case the position in the outer stream has been changed
        self._seek_to_pos()

        buffer = self.outer.read(bytes_to_read)
        self.__pos += len(buffer)
        assert 0 <= self.__pos <= self.length
        return buffer

    def __enter__(self) -> BinaryIO:
        return self

    def close(self) -> None:
        pass

    def fileno(self) -> int:
        raise NotImplementedError

    def flush(self) -> None:
        self.outer.flush()

    def isatty(self) -> bool:
        raise NotImplementedError

    def readable(self) -> bool:
        return self.outer.readable()

    def readline(self, limit: int = ...) -> AnyStr:
        raise NotImplementedError

    def readlines(self, hint: int = ...) -> List[AnyStr]:
        raise NotImplementedError

    def seekable(self) -> bool:
        raise NotImplementedError

    def tell(self) -> int:
        return self.__pos

    def truncate(self, size: Optional[int] = ...) -> int:
        raise NotImplementedError

    def writable(self) -> bool:
        return self.outer.writable()

    def write(self, s: AnyStr) -> int:
        raise NotImplementedError

    def writelines(self, lines: Iterable[AnyStr]) -> None:
        raise NotImplementedError

    def __next__(self) -> AnyStr:
        raise NotImplementedError

    def __iter__(self) -> Iterator[AnyStr]:
        raise NotImplementedError
