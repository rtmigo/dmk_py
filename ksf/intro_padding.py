import random
from typing import BinaryIO

from ksf._05_common import read_or_fail
from ksf._10_randoms import get_fast_random_bytes


class IntroPadding:
    """When the encrypted content always starts with the same bytes, this
    could hypothetically make it easier to crack the cipher. So I put a little
    random padding at the beginning of the file.

    Without this padding, every file would begin with a constant: the version
    of the file format. But if padding is added before that, only the
    approximate position of this constant is known (within 16 bytes range).
    """

    @staticmethod
    def first_byte_to_len(x: int) -> int:
        """Returns number from range 0..15"""
        return x & 15

    @staticmethod
    def gen_bytes():
        # first byte is completely random
        first_byte = random.randint(0, 0xFF)
        result = bytes((first_byte,))

        # the least significant four bits of the first (random) byte
        # indicate the number of bytes remaining: minimum 0, maximum 15
        length = IntroPadding.first_byte_to_len(first_byte)
        assert 0 <= length <= 15

        # generating the random padding
        if length > 0:
            result += get_fast_random_bytes(length)

        assert 1 <= len(result) <= 16
        return result

    @staticmethod
    def skip_in_file(df: BinaryIO):
        # skipping the intro padding
        intro_padding_first_byte = read_or_fail(df, 1)[0]
        intro_length = IntroPadding.first_byte_to_len(intro_padding_first_byte)
        if intro_length > 0:
            read_or_fail(df, intro_length)  # or just seek?
