# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import datetime
import os
import random
from pathlib import Path

from Crypto.Random import get_random_bytes

from ksf._40_imprint import Imprint, HashCollision, \
    name_matches_hash
from ksf._wtf import WritingToTempFile

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


def create_fake(name: str, ref_size: int, target_dir: Path):
    """Creates a fake file. The encoded name of fake file will match `name`,
    but the content is random, so the header does not match.

    ref_size: The size of the real file. The fake file will have
    similar size but randomized.
    """
    target_file = target_dir / Imprint(name).as_str
    if target_file.exists():
        raise HashCollision
    size = ref_size + random.randint(int(-ref_size * 0.75),
                                     int(ref_size * 0.75))
    non_matching_header = get_random_bytes(Imprint.FULL_LEN)
    if name_matches_hash(name, non_matching_header):
        raise HashCollision

    with WritingToTempFile(target_file) as wtf:
        # must be the same as writing the real file
        wtf.dirty.write_bytes(get_random_bytes(size))  # todo chunks?
        set_random_last_modified(wtf.dirty)
        wtf.replace()
