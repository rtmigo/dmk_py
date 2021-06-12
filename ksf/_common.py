# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT
import random
from base64 import urlsafe_b64encode, urlsafe_b64decode, b32encode
from pathlib import Path
from typing import BinaryIO, Tuple

from Crypto.Hash import BLAKE2b
from Crypto.Random import get_random_bytes

from ksf.utils.randoms import get_noncrypt_random_bytes

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


def random_basename() -> str:
    for _ in range(99999):
        length = random.randint(2, 12)
        data = get_noncrypt_random_bytes(length)
        result = b32encode(data).decode('ascii')
        result = result.lower().replace('=', '')
        if contains_digit(result) and contains_alpha(result):
            assert looks_like_random_basename(result)
            return result
    raise RuntimeError("Dead loop prevented")


def looks_like_random_basename(txt: str) -> bool:
    return all(c.isalnum() and c.lower()==c for c in txt) \
           and contains_digit(txt) \
           and contains_alpha(txt)


class InsufficientData(Exception):
    pass


def contains_digit(txt: str) -> bool:
    return any(c.isdigit() for c in txt)


def contains_alpha(txt: str) -> bool:
    return any(c.isalpha() for c in txt)


def unique_filename(parent: Path) -> Path:
    for _ in range(999999):
        file = parent / random_basename()
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
