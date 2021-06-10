# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

"""The file storing the salt value is located in the same directory as the rest
of the files. It has the same incomprehensible base64 name of the same length.

The file can be uniquely identified by the following features:

1) The has the base64 name of the proper length (48 bytes)
2) It is smaller than 1024 bytes
3) Among the files that satisfy the first two conditions, this is the
   first alphabetically

The salt is not secret - and anyone who has studied the principle of the
program will be able to read the salt from the directory.

However, the directory looks totally "random". It is some directory with
base64-encoded 48-byte sequences. It contains at least one file smaller
than 512 bytes.
"""

import random
from pathlib import Path
from typing import Optional, Tuple, Iterable, List

from Crypto.Random import get_random_bytes

from ksf._common import PK_SALT_SIZE, BASENAME_SIZE, \
    bytes_to_fn_str, MAX_SALT_FILE_SIZE, read_or_fail, \
    InsufficientData, looks_like_our_basename


class CannotReadSalt(Exception):
    pass


class NotSaltFilename(CannotReadSalt):
    pass


class TooLargeForSaltFile(CannotReadSalt):
    pass


def _write_smth_to_file(target: Path, first_bytes: bytes):
    if target.exists():
        raise FileExistsError

    data = first_bytes

    # computing the padding size
    max_padding_size = MAX_SALT_FILE_SIZE - len(data)
    assert len(data) + max_padding_size <= MAX_SALT_FILE_SIZE
    padding_size = random.randint(0, MAX_SALT_FILE_SIZE - len(data))

    # adding padding
    data += get_random_bytes(padding_size)
    assert len(data) <= MAX_SALT_FILE_SIZE

    # writing file
    target.write_bytes(data)


def _write_salt_to_file(target: Path) -> bytes:
    salt = get_random_bytes(PK_SALT_SIZE)
    _write_smth_to_file(target, salt)
    return salt


def write_salt_and_fakes(parent: Path) -> Tuple[bytes, Path]:
    salt_and_fakes: List[Path] = list()
    for _ in range(random.randint(1, 8)):
        basename_bytes = get_random_bytes(BASENAME_SIZE)
        basename = bytes_to_fn_str(basename_bytes)
        salt_and_fakes.append(parent/basename)
    salt_and_fakes.sort()

    # writing salt to the first file
    salt_file = salt_and_fakes[0]
    salt_bytes = _write_salt_to_file(salt_file)

    # writing fakes
    for fake_file in salt_and_fakes[1:]:
        _write_salt_to_file(fake_file)

    assert find_salt_in_dir(parent) == salt_bytes

    return salt_bytes, salt_file


def read_salt(file: Path):
    if not looks_like_our_basename(file.name):
        raise NotSaltFilename

    if file.stat().st_size > MAX_SALT_FILE_SIZE:
        raise TooLargeForSaltFile

    with file.open('rb') as f:
        salt = read_or_fail(f, PK_SALT_SIZE)
        # if not read_or_fail(f, BASENAME_SIZE) == basename_bytes:
        #    raise SaltVerificationFailed

    assert len(salt) == PK_SALT_SIZE
    return salt


# def iter_salts_in_dir(parent: Path) -> Iterable[bytes]:
#     for fn in parent.glob('*'):
#         try:
#             yield read_salt(fn)
#         except (CannotReadSalt, InsufficientData):
#             continue


class MoreThanOneSalt(Exception):
    pass


def find_salt_in_dir(parent: Path) -> Optional[bytes]:
    salt_file: Optional[Path] = None
    for fn in sorted(parent.glob('*')):
        if looks_like_our_basename(fn.name) and fn.stat().st_size <= MAX_SALT_FILE_SIZE:
            salt_file = fn
            break

    if salt_file is None:
        return None

    return read_salt(salt_file)
    #
    #
    # salts = list(iter_salts_in_dir(parent))
    # if len(salts) > 1:
    #     raise MoreThanOneSalt
    # if len(salts) <= 0:
    #     return None
    # salt = salts[0]
    # assert len(salt) == PK_SALT_SIZE
    # return salt
