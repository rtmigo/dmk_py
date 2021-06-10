import random
from collections import Iterable
from pathlib import Path

from Crypto.Random import get_random_bytes

from ksf._00_common import PK_SALT_SIZE, BASENAME_SIZE, \
    bytes_to_fn_str, MAX_SALT_FILE_SIZE, fnstr_to_bytes, read_or_fail, \
    InsufficientData


class CannotReadSalt(Exception):
    pass


class NotSaltFilename(CannotReadSalt):
    pass


class SaltVerificationFailed(CannotReadSalt):
    pass


def write_salt(parent: Path) -> Path:
    basename_bytes = get_random_bytes(BASENAME_SIZE)
    basename = bytes_to_fn_str(basename_bytes)

    # the file will start with salt continued with the bytes from filename
    salt = get_random_bytes(PK_SALT_SIZE)
    data = salt + basename_bytes

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

    return file


def read_salt(file: Path):
    basename_bytes = fnstr_to_bytes(file.name)
    if len(basename_bytes) != BASENAME_SIZE:
        raise NotSaltFilename

    with file.open('rb') as f:
        salt = read_or_fail(f, PK_SALT_SIZE)
        if not read_or_fail(f, BASENAME_SIZE) == basename_bytes:
            raise SaltVerificationFailed

    assert len(salt) == PK_SALT_SIZE
    return salt


def iter_salts_in_dir(parent: Path) -> Iterable[bytes]:
    for fn in parent.glob('*'):
        try:
            return read_salt(fn)
        except (CannotReadSalt, InsufficientData):
            continue
