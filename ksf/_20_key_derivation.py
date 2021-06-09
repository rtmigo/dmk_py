# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


from typing import Optional

from Crypto.Protocol.KDF import scrypt

from ksf.lru_cache import LRUCache


class KeyDerivationSettings:
    power = 17


class FasterKeys:
    """The slower the key derivation function, the more reliable it is.
    However, it is very difficult to test slow functions. If the tests do not
    depend on specific hash values, you can use this context manager, which
    will make key derivation much faster."""

    def __init__(self):
        self.original: Optional[int] = None

    def start(self):
        self.original = KeyDerivationSettings.power
        KeyDerivationSettings.power = 3

    def end(self):
        KeyDerivationSettings.power = self.original

    def __enter__(self):
        self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end()


_cache: LRUCache[str, bytes] = LRUCache(9999)


def password_to_key(password: str, salt: bytes, size: int = 16):
    cache_key = '\0'.join((password,
                           str(salt),
                           str(size),
                           str(KeyDerivationSettings.power)))
    x = _cache.get(cache_key)
    if x is None:
        x = _password_to_key_noncached(password, salt, size)
        _cache.put(cache_key, x)
    return x


def _password_to_key_noncached(password: str, salt: bytes, size: int = 16):
    # https://nitratine.net/blog/post/python-gcm-encryption-tutorial/
    # noinspection PyTypeChecker
    return scrypt(password,
                  salt,  # type: ignore
                  key_len=size,
                  N=2 ** KeyDerivationSettings.power,
                  r=8, p=1)
