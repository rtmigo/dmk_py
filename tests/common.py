import random
from base64 import b64encode
from typing import List

from ksf.utils.randoms import get_noncrypt_random_bytes

testing_salt = b"\xef\x87\xffr_\xed\xe2\xc5\x92\x11\x8e'F\xe6-C\xf1" \
               b"\xa9\xd4\x9fu\xc8\x05Y\x8b\xc3\x94\xd1\xbd\x10#B"


def gen_random_content() -> bytes:
    return get_noncrypt_random_bytes(random.randint(0, 16 * 1024))


def gen_random_name() -> str:
    len_bytes = random.randint(0, 20)
    return b64encode(get_noncrypt_random_bytes(len_bytes)).decode()


def gen_random_names(n: int) -> List[str]:
    names = set()
    while len(names) < n:
        names.add(gen_random_name())
    assert len(names) == n
    return list(names)
