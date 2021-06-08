# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import datetime
import os
import random
from base64 import urlsafe_b64encode, urlsafe_b64decode
from pathlib import Path
from typing import Tuple, Optional

from Crypto.Hash import BLAKE2b
from Crypto.Random import get_random_bytes


def bytes_to_str(data: bytes) -> str:
    return urlsafe_b64encode(data).decode('ascii')


def str_to_bytes(data: str) -> bytes:
    return urlsafe_b64decode(data.encode('ascii'))


def half_n_half(salt: bytes) -> Tuple[bytes, bytes]:
    """Splits bytes array in two equal parts (if the array length is even),
    or almost equal (if it's odd)"""
    half = len(salt) >> 1
    a = salt[:half]
    b = salt[half:]
    assert abs(len(a) - len(b)) <= 1
    return a, b


class Imprint:
    """Each name has a conventionally infinite number of imprints
    (2^192 or six octodecillion).

    Each new imprint is unique, although the name is the same.

    Knowing the name, we can tell if the imprint belongs to it.

    Without knowing the name, we can hardly do anything. We cannot
    reconstruct a name from an imprint, or even suggest it. We cannot say
    whether two imprints correspond to the same name or to different ones.

    ==

    Imprint collision can happen in two ways:
    - we will generate two identical imprints for the same name
    - different names will produce the same imprints

    Until we're in a spaceship with infinite improbability drive,
    neither will happen.
    """

    __slots__ = ['__name', '__nonce', '__as_bytes', '__as_str']

    NONCE_LEN = 24
    DIGEST_LEN = 24
    HEADER_LEN = NONCE_LEN + DIGEST_LEN

    def __init__(self, name: str, nonce: bytes = None):
        if len(name) < 1:
            raise ValueError("Name must not be empty")
        self.__name = name
        self.__nonce: Optional[bytes] = nonce
        self.__as_bytes: Optional[bytes] = None
        self.__as_str: Optional[str] = None

    @property
    def name(self):
        return self.__name

    @property
    def nonce(self):
        if self.__nonce is None:
            self.__nonce = get_random_bytes(Imprint.NONCE_LEN)
        return self.__nonce

    @property
    def as_bytes(self) -> bytes:
        if self.__as_bytes is None:
            a, b = half_n_half(self.nonce)
            data_for_hash = a + self.name.encode('utf-8') + b
            h_obj = BLAKE2b.new(digest_bits=Imprint.DIGEST_LEN * 8)
            h_obj.update(data_for_hash)
            result = h_obj.digest() + self.nonce
            assert len(result) == Imprint.HEADER_LEN
            self.__as_bytes = result
        return self.__as_bytes

    @property
    def as_str(self) -> str:
        """Returns the imprint as a string that can be used
        as a filename."""
        if self.__as_str is None:
            self.__as_str = bytes_to_str(self.as_bytes)
        return self.__as_str

    @staticmethod
    def bytes_to_nonce(h: bytes) -> bytes:
        if len(h) != Imprint.HEADER_LEN:
            raise ValueError
        return h[-Imprint.NONCE_LEN:]


def name_matches_encoded(name: str, encoded: str) -> bool:
    nonce = Imprint.bytes_to_nonce(str_to_bytes(encoded))
    assert len(nonce) == Imprint.NONCE_LEN
    return encoded == Imprint(name, nonce=nonce).as_str


def name_matches_hash(name: str, header: bytes) -> bool:
    nonce = Imprint.bytes_to_nonce(header)
    return Imprint(name, nonce=nonce).as_bytes == header


class HashCollision(Exception):
    """The program works correctly, based on the assumption that we always get
    different hashes from different data. We also assume that the generated
    nonces never match.

    In theory, both assumptions are wrong. In practice, the chance of getting
    such a collision is much less than the inoperability of the program for
    other reasons."""
    pass


MICROSECONDS_PER_DAY = 24 * 60 * 60 * 1000 * 1000
assert datetime.timedelta(microseconds=MICROSECONDS_PER_DAY) \
           .total_seconds() == 60 * 60 * 24


def random_datetime(max_days_ago=366) -> datetime.datetime:
    mcs = random.randint(0, MICROSECONDS_PER_DAY * max_days_ago)
    delta = datetime.timedelta(microseconds=mcs)
    return datetime.datetime.now() - delta


def set_file_last_modified(file: Path, dt: datetime.datetime):
    dt_epoch = dt.timestamp()
    os.utime(str(file), (dt_epoch, dt_epoch))


