# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import datetime
import os
import random
from pathlib import Path

from Crypto.Random import get_random_bytes

from ksf._00_wtf import WritingToTempFile
from ksf._20_key_derivation import FilesetPrivateKey
from ksf._40_imprint import Imprint, HashCollision, \
    pk_matches_imprint_bytes

MICROSECONDS_PER_DAY = 24 * 60 * 60 * 1000 * 1000
assert datetime.timedelta(microseconds=MICROSECONDS_PER_DAY) \
           .total_seconds() == 60 * 60 * 24


def _random_datetime(max_days_ago=366) -> datetime.datetime:
    mcs = random.randint(0, MICROSECONDS_PER_DAY * max_days_ago)
    delta = datetime.timedelta(microseconds=mcs)
    return datetime.datetime.now() - delta


def _set_file_last_modified(file: Path, dt: datetime.datetime):
    dt_epoch = dt.timestamp()
    os.utime(str(file), (dt_epoch, dt_epoch))


def set_random_last_modified(file: Path):
    _set_file_last_modified(file, _random_datetime())


def create_surrogate(fpk: FilesetPrivateKey, ref_size: int, target_dir: Path):
    """Creates a surrogate file.

    The file name of the surrogate will be the correct imprint from the
    [name]. But the file content is random, so the file header is not
    a correct imprint from [name].

    Knowing the name we can easily find all the surrogates and real files
    for the name. We can differentiate the real file from the surrogate
    by the header (only for real files it contains the imprint).

    ref_size: The size of the real file. The surrogate file will have
    similar size but randomized.
    """
    target_file = target_dir / Imprint(fpk).as_str
    if target_file.exists():
        raise HashCollision
    size = randomized_size(ref_size)
    non_matching_header = get_random_bytes(Imprint.FULL_LEN)
    if pk_matches_imprint_bytes(fpk, non_matching_header):
        raise HashCollision

    with WritingToTempFile(target_file) as wtf:
        # must be the same as writing the real file
        wtf.dirty.write_bytes(get_random_bytes(size))  # todo chunks?
        set_random_last_modified(wtf.dirty)
        wtf.replace()


def randomized_size(real_size: int) -> int:
    # must be used when creating both surrogates and real files
    return real_size + random.randint(0, round(real_size / 2))
