# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import unittest
from functools import lru_cache
from typing import Optional, NamedTuple

import argon2.low_level

from dmk._common import KEY_SALT_SIZE
from dmk.a_base._05_codename import CodenameAscii


class ArgonParams(NamedTuple):
    time: int
    mem: int


class CodenameKey:
    """The 256-bit private key.

    The private key is derived from the codename. Computing a private key
    from a name is resource-intensive. We will do this at most once. After
    that, instead of a name, we always use the key or its derivatives.

    """

    __slots__ = ["as_bytes", "codename"]

    __time_cost = 4
    __mem_cost = 131072  # 128 MiB

    @classmethod
    def is_standard_params(cls) -> bool:
        return cls.__time_cost == 4 and cls.__mem_cost == 131072

    @classmethod
    def get_params(cls) -> ArgonParams:
        return ArgonParams(cls.__time_cost, cls.__mem_cost)

    @classmethod
    def set_params(cls, time_cost: int, mem_cost: int) -> None:
        cls.__time_cost = time_cost
        cls.__mem_cost = mem_cost

    # Argon2id 128 MiB, parallelism 8
    # TC | Intel i7-8700K | AMD A9-9420e
    # ---|----------------|--------------
    #  6 | 0.12 sec       | 0.83 sec
    #  4 | 0.09 sec       | 0.58 sec

    # Argon2id 128 MiB, parallelism 4
    # TC | Intel i7-8700K | AMD A9-9420e
    # ---|----------------|--------------
    #  9 | 0.19 sec       | 1.2 sec
    #  6 | 0.13 sec       | ?

    def __init__(self, password: str, salt: bytes):
        if len(salt) != KEY_SALT_SIZE:
            raise ValueError("Wrong salt length")
        self.codename = password
        self.as_bytes = _password_to_key_cached(
            password=CodenameAscii.to_ascii(password),
            salt=salt,
            mem_cost=CodenameKey.__mem_cost,
            time_cost=CodenameKey.__time_cost)


@lru_cache(10000)
def _password_to_key_cached(password: bytes, salt: bytes, mem_cost: int,
                            time_cost: int):
    return _password_to_key_noncached(password=password, salt=salt,
                                      mem_cost=mem_cost, time_cost=time_cost)


def _password_to_key_noncached(password: bytes, salt: bytes, mem_cost: int,
                               time_cost: int):
    # in 2021 constants in argon2-cffi are following:
    #   DEFAULT_RANDOM_SALT_LENGTH = 16
    #   DEFAULT_HASH_LENGTH = 16
    #   DEFAULT_TIME_COST = 2
    #   DEFAULT_MEMORY_COST = 102400      # 102400 KiB = 100 MiB
    #   DEFAULT_PARALLELISM = 8

    HASH_LEN = 32

    result = argon2.low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=mem_cost,
        parallelism=8,
        type=argon2.low_level.Type.ID,
        version=0x13,
        hash_len=HASH_LEN
    )

    # print(argon_raw)

    assert len(result) == HASH_LEN
    return result


class FasterKDF:
    """The slower the key derivation function, the more reliable it is.
    However, it is very difficult to test slow functions. If the tests do not
    depend on specific hash values, you can use this context manager, which
    will make key derivation much faster."""

    def __init__(self):
        self.mem_original: Optional[int] = None
        self.time_original: Optional[int] = None

    def start(self):
        self.time_original, self.mem_original = CodenameKey.get_params()
        CodenameKey.set_params(1, 1024)

    def end(self):
        CodenameKey.set_params(self.time_original, self.mem_original)

    def __enter__(self):
        self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end()


if __name__ == "__main__":
    unittest.main()
    pass
