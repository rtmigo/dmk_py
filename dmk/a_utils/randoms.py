# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import datetime
import os
import random
from base64 import b32encode, urlsafe_b64encode, urlsafe_b64decode
from pathlib import Path

from Crypto.Random import get_random_bytes

from dmk._common import CODENAME_LENGTH_BYTES


# todo remove unused funcs


def get_noncrypt_random_bytes(n: int):
    return bytes(random.getrandbits(8) for _ in range(n))


MICROSECONDS_PER_DAY = 24 * 60 * 60 * 1000 * 1000


def random_codename_fullsize() -> str:
    # todo test
    chars = ''.join(chr(i) for i in range(1, 128))
    return ''.join(random.choice(chars) for _ in range(CODENAME_LENGTH_BYTES))


def _random_datetime(max_days_ago: float = 366) -> datetime.datetime:
    # todo remove?
    mcs = random.randint(0, round(MICROSECONDS_PER_DAY * max_days_ago))
    delta = datetime.timedelta(microseconds=mcs)
    return datetime.datetime.now() - delta


def _set_file_last_modified(file: Path, dt: datetime.datetime):
    # todo remove?
    dt_epoch = dt.timestamp()
    os.utime(str(file), (dt_epoch, dt_epoch))


def set_random_last_modified(file: Path):
    # todo remove?
    _set_file_last_modified(file, _random_datetime(max_days_ago=365.2425 * 10))


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
    return all(c.isalnum() and c.lower() == c for c in txt) \
           and contains_digit(txt) \
           and contains_alpha(txt)


def contains_digit(txt: str) -> bool:
    return any(c.isdigit() for c in txt)


def contains_alpha(txt: str) -> bool:
    return any(c.isalpha() for c in txt)


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


def unique_filename(parent: Path) -> Path:
    for _ in range(999999):
        file = parent / random_basename()
        if not file.exists():
            return file
    raise RuntimeError("Cannot find unique filename")
