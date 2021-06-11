# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT
import random
from base64 import urlsafe_b64encode, urlsafe_b64decode
from pathlib import Path
from typing import BinaryIO, Tuple

from Crypto.Hash import BLAKE2b
from Crypto.Random import get_random_bytes

PK_SALT_SIZE = 32
PK_SIZE = 32
BASENAME_SIZE = 48

MAX_SALT_FILE_SIZE = 1023
MIN_DATA_FILE_SIZE = MAX_SALT_FILE_SIZE + 1

assert MIN_DATA_FILE_SIZE > MAX_SALT_FILE_SIZE
assert PK_SIZE * 8 == 256


def read_or_fail(f: BinaryIO, n: int) -> bytes:
    result = f.read(n)
    if len(result) != n:
        raise InsufficientData
    return result


def looks_like_our_basename(txt: str) -> bool:
    return '.' not in txt
    # try:
    #     bytes = fnstr_to_bytes(txt)
    #     return len(bytes) == BASENAME_SIZE
    # except ValueError:
    #     return False


class InsufficientData(Exception):
    pass


def unique_filename(parent: Path) -> Path:
    for _ in range(999999):
        # length is not secure, but bytes are.
        # How to make the length secure?
        basename = ''
        for _ in range(random.randint(2, 12)):
            # on windows files are not really case-sensitive.
            # So we prefer lowercase
            basename += random.choice('abcdefghijklmnopqrstuvwxyz0123456789')

        # basename = bytes_to_fn_str(get_random_bytes(length))
        file = parent / basename
        if not file.exists():
            return file
    raise RuntimeError("Cannot find unique filename")


def unique_filename_old(parent: Path) -> Path:
    for _ in range(999999):
        # length is not secure, but bytes are.
        # How to make the length secure?
        length = random.randint(1, 12)
        basename = bytes_to_fn_str(get_random_bytes(length))
        file = parent / basename
        if not file.exists():
            return file
    raise RuntimeError("Cannot find unique filename")


def bytes_to_fn_str(data: bytes) -> str:
    # if len(data) != IMPRINT_SIZE:
    #    raise ValueError
    return urlsafe_b64encode(data).decode('ascii')


def fnstr_to_bytes(data: str) -> bytes:
    return urlsafe_b64decode(data.encode('ascii'))


def half_n_half(salt: bytes) -> Tuple[bytes, bytes]:
    """Splits bytes array in two equal parts (if the array length is even),
    or almost equal (if it's odd)"""
    half = len(salt) >> 1
    a = salt[:half]
    b = salt[half:]
    assert abs(len(a) - len(b)) <= 1
    return a, b


def blake192(data: bytes, salt: bytes) -> bytes:
    h_obj = BLAKE2b.new(digest_bits=192)
    a, b = half_n_half(salt)
    h_obj.update(a + data + b)
    return h_obj.digest()
