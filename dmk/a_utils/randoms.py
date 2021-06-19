# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import datetime
import os

import random
from pathlib import Path


def get_noncrypt_random_bytes(n: int):
    return bytes(random.getrandbits(8) for _ in range(n))


MICROSECONDS_PER_DAY = 24 * 60 * 60 * 1000 * 1000


def _random_datetime(max_days_ago: float = 366) -> datetime.datetime:
    mcs = random.randint(0, round(MICROSECONDS_PER_DAY * max_days_ago))
    delta = datetime.timedelta(microseconds=mcs)
    return datetime.datetime.now() - delta


def _set_file_last_modified(file: Path, dt: datetime.datetime):
    dt_epoch = dt.timestamp()
    os.utime(str(file), (dt_epoch, dt_epoch))


def set_random_last_modified(file: Path):
    _set_file_last_modified(file, _random_datetime(max_days_ago=365.2425 * 10))
