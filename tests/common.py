# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import datetime
import random
from base64 import b64encode
from pathlib import Path
from typing import List, Set

from dmk._common import KEY_SALT_SIZE
from dmk.a_utils.randoms import get_noncrypt_random_bytes

testing_salt = bytes(
    [9, 208, 40, 189, 20, 243, 43, 249, 92, 217, 154, 31, 26, 87, 141, 11, 123,
     135, 30, 28, 244, 158, 249, 124, 253, 185, 233, 143, 129, 151, 66, 110, 19,
     51, 73, 87, 244, 192]
)


def gen_random_content(min_size=0, max_size=1024) -> bytes:
    return get_noncrypt_random_bytes(random.randint(min_size, max_size))


def gen_random_string() -> str:
    len_bytes = random.randint(0, 20)
    return b64encode(get_noncrypt_random_bytes(len_bytes)).decode()


def gen_random_name() -> str:
    len_bytes = random.randint(0, 20)
    s = b64encode(get_noncrypt_random_bytes(len_bytes)).decode()
    s = s[:20]
    return s


def gen_random_names(n: int) -> List[str]:
    names: Set[str] = set()
    while len(names) < n:
        names.add(gen_random_name())
    assert len(names) == n
    return list(names)


def dates_are_random(files: List[Path]) -> bool:
    if len(files) < 3:
        raise ValueError(f"Only {len(files)} files! Need 3.")
    dates = [datetime.date.fromtimestamp(f.stat().st_mtime) for f in files]
    return len(set(dates)) >= 2


def sizes_are_random(files: List[Path]) -> bool:
    if len(files) < 3:
        raise ValueError(f"Only {len(files)} files! Need 3.")
    sizes = [f.stat().st_size for f in files]
    return len(set(sizes)) >= 2


if __name__ == "__main__":
    print(list(get_noncrypt_random_bytes(KEY_SALT_SIZE)))
