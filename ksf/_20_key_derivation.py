# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

from functools import lru_cache
from typing import Optional

from Crypto.Protocol.KDF import scrypt


class FilesetPrivateKey:
    """A fileset is a set of files related to the same item. One of these
    files contains encrypted item data, others are fake or contain outdated
    data.

    The item name is a secret: knowing the name, we can not only find the
    corresponding files, but also decrypt the data.

    The private key is derived from the item name. Computing a private key
    from a name is the most resource-intensive task. We try to do this at
    most once. After that, instead of a name, we always use only the key.

    ----

    The salt here is a constant common to all instances of the application.
    This makes the password sufficient to obtain the private key on any
    computer.

    In theory, it would be better for each user to have their own salt. But
    while the number of users is small, and the app is not a tempting target,
    keeping salt as a constant common to all is a rational compromise.
    """

    __slots__ = ["as_bytes"]

    _power = 18  # larger values = slower function, better protection

    salt = b"\xef\x87\xffr_\xed\xe2\xc5\x92\x11\x8e'F\xe6-C\xf1" \
           b"\xa9\xd4\x9fu\xc8\x05Y\x8b\xc3\x94\xd1\xbd\x10#B"

    def __init__(self, password: str):
        self.as_bytes = _password_to_key_cached(
            password,
            self.salt,
            size=32,
            pwr=FilesetPrivateKey._power)


@lru_cache(10000)
def _password_to_key_cached(password: str, salt: bytes, size: int, pwr: int):
    return _password_to_key_noncached(password, salt, size, pwr)


def _password_to_key_noncached(password: str, salt: bytes, size: int, pwr: int):
    # https://nitratine.net/blog/post/python-gcm-encryption-tutorial/
    # noinspection PyTypeChecker
    return scrypt(password,
                  salt,  # type: ignore
                  key_len=size,
                  N=2 ** pwr,
                  r=8, p=1)


class FasterKeys:
    """The slower the key derivation function, the more reliable it is.
    However, it is very difficult to test slow functions. If the tests do not
    depend on specific hash values, you can use this context manager, which
    will make key derivation much faster."""

    def __init__(self):
        self.original: Optional[int] = None

    def start(self):
        self.original = FilesetPrivateKey._power
        FilesetPrivateKey._power = 2

    def end(self):
        FilesetPrivateKey._power = self.original

    def __enter__(self):
        self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end()


if __name__ == "__main__":
    from Crypto.Random import get_random_bytes

    print(tuple(get_random_bytes(32)))
