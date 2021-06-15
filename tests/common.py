import datetime
import random
from base64 import b64encode
from pathlib import Path
from typing import List, Set

from codn.a_utils.randoms import get_noncrypt_random_bytes

testing_salt = b"\xef\x87\xffr_\xed\xe2\xc5\x92\x11\x8e'F\xe6-C\xf1" \
               b"\xa9\xd4\x9fu\xc8\x05Y\x8b\xc3\x94\xd1\xbd\x10#B"


def gen_random_content(min_size=0, max_size=1024) -> bytes:
    return get_noncrypt_random_bytes(random.randint(min_size, max_size))


def gen_random_name() -> str:
    len_bytes = random.randint(0, 20)
    return b64encode(get_noncrypt_random_bytes(len_bytes)).decode()


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
