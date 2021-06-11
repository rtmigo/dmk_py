# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

"""The file storing the salt value is located in the same directory as the rest
of the files. It has the same incomprehensible base64 name of the same length.

The file can be uniquely identified by the following features:

1) It is smaller than 1024 bytes
2) It's name does not contain dot
3) Among the files that satisfy the first two conditions, this is the
   first alphabetically

The salt is not secret - and anyone who has studied the principle of the
program will be able to read the salt from the directory.

However, the directory looks totally "random". It is some directory with
base64-encoded random name. It contains at least one file smaller than
1024 bytes.
"""

import random
import stat
from pathlib import Path
from typing import Optional, List, NamedTuple

from Crypto.Random import get_random_bytes

from ksf._common import PK_SALT_SIZE, MAX_SALT_FILE_SIZE, read_or_fail, \
    looks_like_our_basename, unique_filename
from ksf.cryptodir.fileset._10_fakes import set_random_last_modified


class SaltFileError(Exception):
    pass


class SaltFileBadName(SaltFileError):
    pass


class SaltFileIsNotFile(SaltFileError):
    pass


class SaltFileTooLarge(SaltFileError):
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


class SaltAndFakes(NamedTuple):
    salt: bytes
    file: Path
    fakes: List[Path]


def write_salt_and_fakes(parent: Path,
                         min_fakes=1,
                         max_fakes=8) -> SaltAndFakes:
    # generating new filenames that are not repeating
    # and do not exist as files
    salt_and_fakes: List[Path] = []
    n = random.randint(min_fakes, max_fakes)
    while len(salt_and_fakes) < n:
        fn = unique_filename(parent)
        if fn not in salt_and_fakes:
            salt_and_fakes.append(fn)

    # sorting alphabetically
    salt_and_fakes.sort()

    # writing salt to the first file
    salt_file = salt_and_fakes[0]
    salt_bytes = _write_salt_to_file(salt_file)

    # writing fakes
    fakes = salt_and_fakes[1:]
    for fake_file in fakes:
        _write_salt_to_file(fake_file)

    assert find_salt_in_dir(parent) == salt_bytes

    for f in salt_and_fakes:
        set_random_last_modified(f)

    return SaltAndFakes(salt_bytes, salt_file, fakes)


def read_salt(file: Path):
    if not looks_like_our_basename(file.name):
        raise SaltFileBadName

    fs = file.stat()
    if not stat.S_ISREG(fs.st_mode):
        raise SaltFileIsNotFile
    # if stat.S_ISDIR(fs.st_mode) or stat.S_ISLNK(fs.st_mode) or
    # fs.st_flags

    if file.stat().st_size > MAX_SALT_FILE_SIZE:
        raise SaltFileTooLarge

    with file.open('rb') as f:
        salt = read_or_fail(f, PK_SALT_SIZE)

    assert len(salt) == PK_SALT_SIZE
    return salt


def find_salt_in_dir(parent: Path) -> Optional[bytes]:
    salt_file: Optional[Path] = None
    for fn in sorted(parent.glob('*'), key=lambda p: p.name):
        print(f"trying salt {fn}")
        if looks_like_our_basename(
                fn.name) and fn.stat().st_size <= MAX_SALT_FILE_SIZE:
            salt_file = fn
            break

    if salt_file is None:
        return None

    return read_salt(salt_file)
