import random
from typing import BinaryIO

from ksf._05_common import read_or_fail
from ksf._10_randoms import get_fast_random_bytes


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


class IntroPadding:
    """When the encrypted content always starts with the same bytes, this
    could hypothetically make it easier to crack the cipher. So I put a little
    random padding at the beginning of the file.

    Without this padding, every file would begin with a constant: the version
    of the file format. But if padding is added before that, only the
    approximate position of this constant is known (within 64 bytes range).
    """

    __slots__ = ["max_len"]

    def __init__(self, maxlen: int):

        # technically 1 is a power of two (2**0), but the minimum value is 2.
        # So all max_len values are positive and even

        if not 2 <= maxlen <= 0xFF:
            raise ValueError("Range error")
        if not _is_power_of_two(maxlen):
            raise ValueError("not a power of two")
        self.max_len = maxlen

    def first_byte_to_len(self, x: int) -> int:
        """Returns number from range 0..63"""
        if not 0 <= x <= 0xFF:
            raise ValueError
        return x & (self.max_len - 1)

    def gen_bytes(self):
        # first byte is completely random
        first_byte = random.randint(0, 0xFF)
        result = bytes((first_byte,))

        # the least significant four bits of the first (random) byte
        # indicate the number of bytes remaining: minimum 0, maximum 15
        length = self.first_byte_to_len(first_byte)
        assert 0 <= length <= self.max_len - 1

        # generating the random padding
        if length > 0:
            result += get_fast_random_bytes(length)

        assert 1 <= len(result) <= 64
        return result

    def skip_in_file(self, df: BinaryIO):
        # skipping the intro padding
        intro_padding_first_byte = read_or_fail(df, 1)[0]
        intro_length = self.first_byte_to_len(intro_padding_first_byte)
        if intro_length > 0:
            read_or_fail(df, intro_length)  # or just seek?
