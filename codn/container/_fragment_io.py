import io
from typing import BinaryIO


class FragmentIO(io.RawIOBase, BinaryIO):
    """Allows reading data from a fragment of a stream.

    The fragment will look like a stream. But this object will only allow
    reading the bytes that belong to the fragment. The seek method will also
    only set the position within the fragment.

    WARNING (OUTDATED:)
    -------

    If you perform an operation on an external stream while this object is in
    use, it will change the position in the external stream and break
    everything.

    To prevent this from happening, before using this object (again), you
    should call seek(0, io.SEEK_CUR).
    """

    def __init__(self, outer: BinaryIO, start: int, length: int):
        super().__init__()
        self.outer = outer
        self.inner_pos = 0  # local position
        self.outer_start = start  # location of substream in the outer stream
        self.length = length
        self._seeked = False

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
        return buffer