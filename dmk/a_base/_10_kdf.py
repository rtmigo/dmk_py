# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT
import unittest
from base64 import b64decode
from functools import lru_cache
from typing import Optional, Tuple, NamedTuple

import argon2.low_level

from dmk._common import KEY_SALT_SIZE
from dmk.a_base._05_codename import CodenameAscii


# from argon2 import PasswordHasher
# import hashlib

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

    # _power = 17  # larger values = slower function, more secure
    __time_cost = 4
    __mem_cost = 131072  # 128MB # 102400

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

    # scrypt
    # pow | Intel i7-8700K | AMD A9-9420e
    # ----|----------------|--------------
    #  17 | 0.32 sec       | 0.58 sec
    #  18 | 0.65 sec       | 1.17 sec

    def __init__(self, password: str, salt: bytes):
        if len(salt) != KEY_SALT_SIZE:
            raise ValueError("Wrong salt length")
        self.codename = password
        self.as_bytes = _password_to_key_cached(
            CodenameAscii.to_ascii(password),
            salt,
            mem_cost=CodenameKey.__mem_cost,
            time_cost=CodenameKey.__time_cost)


@lru_cache(10000)
def _password_to_key_cached(password: bytes, salt: bytes, mem_cost: int,
                            time_cost: int):
    return _password_to_key_noncached(password, salt, mem_cost, time_cost)


# References salt (88, 34, 3, 68, 37, 216, 7, 202, 134, 57, 99, 183, 8, 181, 155, 116, 118, 20, 254, 93, 111, 198, 85, 132)
# argon str b'$argon2id$v=19$m=131072,t=4,p=8$WCIDRCXYB8qGOWO3CLWbdHYU/l1vxlWE$/B9WWGjpyvrY3lBzjSAfWwjIaNnTHa/xXlePfVSftIQ'

# References salt (88, 34, 3, 68, 37, 216, 7, 202, 134, 57, 99, 183, 8, 181, 155, 116, 118, 20, 254, 93, 111, 198, 85, 132)
# argon str b'$argon2id$v=19$m=131072,t=3,p=8$WCIDRCXYB8qGOWO3CLWbdHYU/l1vxlWE$Bndl/hSde014akF697iVthg3epJbw7e6IJOfKSOczZM'


def _password_to_key_noncached(password: bytes, salt: bytes, mem_cost: int,
                               time_cost: int):
    # https://nitratine.net/blog/post/python-gcm-encryption-tutorial/

    # 2021:
    # DEFAULT_RANDOM_SALT_LENGTH = 16
    # DEFAULT_HASH_LENGTH = 16
    # DEFAULT_TIME_COST = 2
    # DEFAULT_MEMORY_COST = 102400
    # DEFAULT_PARALLELISM = 8

    # print(argon2.low_level.ARGON2_VERSION)

    # assert time_cost != 3

    argon_str = argon2.low_level.hash_secret(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=mem_cost,  # default for 2021 is 102400, ~100MB
        parallelism=8,
        type=argon2.low_level.Type.ID,
        version=19,
        hash_len=32
    )

    # print("argon str", argon_str)

    # $argon2i$v=19$m=512,t=3,p=2$c29tZXNhbHQ$SqlVijFGiPG+935vDSGEsA
    assert b64decode(argon_str.split(b'$')[-2]) == salt

    digest = argon_str.rpartition(b'$')[-1]
    # print(digest)
    return b64decode(digest + b'==')

    # ph = PasswordHasher()

    # # noinspection PyTypeChecker
    # return scrypt(password, # type: ignore
    #               salt,  # type: ignore
    #               key_len=size,
    #               N=2 ** pwr,
    #               r=8, p=1)


# def _password_to_key_noncached(password: bytes, salt: bytes, size: int, pwr: int):
#     # https://nitratine.net/blog/post/python-gcm-encryption-tutorial/
#
#     return hashlib.scrypt(password, salt=salt,
#                   dklen=size,
#                   n=2 ** pwr,
#                           r=16, p=1, #maxmem=1024*1024*32
#                   #r=8, p=1
#                           )

class FasterKDF:
    """The slower the key derivation function, the more reliable it is.
    However, it is very difficult to test slow functions. If the tests do not
    depend on specific hash values, you can use this context manager, which
    will make key derivation much faster."""

    def __init__(self):
        self.mem_original: Optional[int] = None
        self.time_original: Optional[int] = None

    def start(self):
        # pass

        self.time_original, self.mem_original = CodenameKey.get_params()

        # self.time_original = CodenameKey._time_cost
        # self.mem_original = CodenameKey._mem_cost
        CodenameKey.set_params(1, 1024)
        # CodenameKey._time_cost = 1
        # CodenameKey._mem_cost = 1024

    def end(self):
        CodenameKey.set_params(self.time_original, self.mem_original)
        # pass
        # CodenameKey._time_cost = self.time_original
        # CodenameKey._mem_cost = self.mem_original

    def __enter__(self):
        self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end()


# if __name__ == "__main__":
#     from Crypto.Random import get_random_bytes
#
#     #print(tuple(get_random_bytes(32)))

if __name__ == "__main__":
    unittest.main()
    pass
    # salt = get_random_bytes(24)
    # for _ in range(10):
    #     t = time.monotonic()
    #     _password_to_key_noncached(b'12345678', salt, CodenameKey._time_cost)
    #     print(time.monotonic()-t)
