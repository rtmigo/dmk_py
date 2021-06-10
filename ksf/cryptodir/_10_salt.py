# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

"""The file storing the salt value is located in the same directory as the rest
of the files. It has the same incomprehensible base64 name of the same length.

The main thing that distinguishes it: the file size is less than a kilobyte
(up to 1023 bytes).

The salt is not secret - and anyone who has studied the principle of the
program will be able to read the salt from the directory.

Filename tricks make the origin of the data obscure. We will just have a
directory with "random" data with "random" 48-byte names, and in which there
is only one file less than a kilobyte.

It can be hypothesized that this directory was created by this program, but
without having at least one password, it is impossible to prove.
"""

import random
from pathlib import Path
from typing import Optional, Tuple, Iterable

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


def write_salt(parent: Path) -> Tuple[bytes, Path]:
    basename_bytes = get_random_bytes(BASENAME_SIZE)
    basename = bytes_to_fn_str(basename_bytes)

    # the file will start with salt continued with the bytes from filename
    salt = get_random_bytes(PK_SALT_SIZE)
    data = salt  # + basename_bytes

    # computing the padding size
    max_padding_size = MAX_SALT_FILE_SIZE - len(data)
    assert len(data) + max_padding_size <= MAX_SALT_FILE_SIZE
    padding_size = random.randint(0, MAX_SALT_FILE_SIZE - len(data))

    # adding padding
    data += get_random_bytes(padding_size)
    assert len(data) <= MAX_SALT_FILE_SIZE

    # writing file
    file = parent / basename
    assert not file.exists()
    file.write_bytes(data)

    return salt, file


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


def iter_salts_in_dir(parent: Path) -> Iterable[bytes]:
    for fn in parent.glob('*'):
        try:
            yield read_salt(fn)
        except (CannotReadSalt, InsufficientData):
            continue


class MoreThanOneSalt(Exception):
    pass


def find_salt_in_dir(parent: Path) -> Optional[bytes]:
    salts = list(iter_salts_in_dir(parent))
    if len(salts) > 1:
        raise MoreThanOneSalt
    if len(salts) <= 0:
        return None
    salt = salts[0]
    assert len(salt) == PK_SALT_SIZE
    return salt
