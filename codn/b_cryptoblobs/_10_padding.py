# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import random
from typing import BinaryIO

from codn._common import read_or_fail
from codn.a_utils.randoms import get_noncrypt_random_bytes


def _is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def _set_highest_bit(x: int) -> int:
    if not 0 <= x <= 0xFF:
        raise ValueError
    return x | 0x80


def _is_highest_bit_set(x: int) -> bool:
    if not 0 <= x <= 0xFF:
        raise ValueError
    return x & 0x80 != 0


def _first_byte_to_len(x: int, maxlen: int) -> int:
    if not 2 <= maxlen <= 128:
        raise ValueError("must be from rang 0<=x<=128")
    if not _is_power_of_two(maxlen):
        raise ValueError("not a power of two")
    if not _is_highest_bit_set(x):
        raise ValueError("Highest bit not set")
    return (x & (maxlen - 1))


def _random_first_byte() -> int:
    x = random.randint(0, 0x7F)
    x = _set_highest_bit(x)
    return x


class IntroPadding:
    """When the encrypted content always starts with the same bytes, this
    could hypothetically make it easier to crack the cipher. So I put a little
    random padding at the beginning of the file.

    Without this padding, every file would begin with a constant: the version
    of the file format. But if padding is added before that, only the
    approximate position of this constant is known (within 64 bytes range).
    """

    __slots__ = ["max_len"]

    def __init__(self, max_len: int):

        # technically 1 is a power of two (2**0), but the minimum value is 2.
        # So all max_len values are positive and even

        if not 2 <= max_len <= 0x80:
            raise ValueError("Range error")
        if not _is_power_of_two(max_len):
            raise ValueError("not a power of two")
        self.max_len = max_len

    def first_byte_to_len(self, x: int) -> int:
        return _first_byte_to_len(x, self.max_len)
        # """Returns number from range 0..63"""
        # if not 0 <= x <= 0xFF:
        #     raise ValueError
        # return x & (self.max_len - 1)

    def gen_bytes(self):
        # The first byte is almost random.
        #
        # Its bits look like that: 1RRRSSSS. The number of Rs and Ls
        # depends on max_len.
        #
        # The lower bits (SSSS) of the first byte store the padding size: the
        # number of bytes to skip. And those bits are random.
        #
        # Higher bits (RRR) are random without any meaning.
        #
        # But the highest bit is always set to 1. If we ever change our mind
        # about starting encrypted data with padding, or decide to change the
        # padding format, we can communicate this with the same bit set to
        # zero.
        #
        # Setting the bit to constant is not good. The first byte will be
        # encrypted. But now a potential brute-forcer knows that the first
        # bit inside the encryption is one. This poses a problem very
        # hypothetically. It is unlikely that anyone would adopt the
        # knowledge of a single bit.

        first_byte = _random_first_byte()
        assert _is_highest_bit_set(first_byte)

        result = bytes((first_byte,))

        # the least significant four bits of the first (random) byte
        # indicate the number of bytes remaining: minimum 0, maximum 15
        length = self.first_byte_to_len(first_byte)
        assert 0 <= length < self.max_len

        # generating the random padding
        if length > 0:
            result += get_noncrypt_random_bytes(length)

        assert 0 <= len(result) < 128
        return result

    def skip_in_file(self, df: BinaryIO):
        # skipping the intro padding
        intro_padding_first_byte = read_or_fail(df, 1)[0]
        intro_length = self.first_byte_to_len(intro_padding_first_byte)
        if intro_length > 0:
            read_or_fail(df, intro_length)  # or just seek?
