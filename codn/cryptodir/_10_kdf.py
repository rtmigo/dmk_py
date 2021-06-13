# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

from functools import lru_cache
from typing import Optional

from Crypto.Protocol.KDF import scrypt

from codn._common import PK_SALT_SIZE


class FilesetPrivateKey:
    """The 256-bit private key.

    Fileset is a set of files related to the same item. One of these
    files contains encrypted item data, others are fake or contain outdated
    data.

    The item name is a secret: knowing the name, we can not only find the
    corresponding files, but also decrypt the data.

    The private key is derived from the item name. Computing a private key
    from a name is resource-intensive. We will do this at most once. After
    that, instead of a name, we always use the key or its derivatives.
    """

    __slots__ = ["as_bytes"]

    _power = 17  # larger values = slower function, more secure

    # pow | Intel i7-8700K | AMD A9-9420e
    # ----|----------------|--------------
    #  17 | 0.32 sec       | 0.58 sec
    #  18 | 0.65 sec       | 1.17 sec

    def __init__(self, password: str, salt: bytes):
        if len(salt) != PK_SALT_SIZE:
            raise ValueError("Wrong salt length")
        self.as_bytes = _password_to_key_cached(
            password,
            salt,
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


class FasterKDF:
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

# if __name__ == "__main__":
#     from Crypto.Random import get_random_bytes
#
#     #print(tuple(get_random_bytes(32)))
