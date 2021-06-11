# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import binascii
from typing import Optional

from Crypto.Random import get_random_bytes

from ksf._common import bytes_to_fn_str, blake192, BASENAME_SIZE
from ksf.cryptodir._10_kdf import FilesetPrivateKey


class Imprint:
    """Each PK has a conventionally infinite number of imprints
    (2^192 or six octodecillion).

    Each new imprint is unique, although the PK is the same.

    Knowing the PK, we can tell if the imprint belongs to it.

    Without knowing the PK, we can hardly do anything. We cannot
    reconstruct a PK from an imprint, or even suggest it. We cannot say
    whether two imprints correspond to the same PK or to different ones.

    ==

    Imprint collision can happen in two ways:
    - we will generate two identical imprints for the same name
    - different names will produce the same imprints

    Until we're in a spaceship with infinite improbability drive,
    neither will happen.
    """

    __slots__ = ['__private_key', '__salt', '__as_bytes', '__as_str']

    NONCE_LEN = 24
    DIGEST_LEN = 24
    FULL_LEN = NONCE_LEN + DIGEST_LEN

    def __init__(self, pk: FilesetPrivateKey, nonce: bytes = None):
        if not isinstance(pk, FilesetPrivateKey):
            raise TypeError
        self.__private_key = pk
        self.__salt: Optional[bytes] = nonce
        self.__as_bytes: Optional[bytes] = None
        self.__as_str: Optional[str] = None

    @property
    def private_key(self) -> FilesetPrivateKey:
        return self.__private_key

    @property
    def nonce(self):
        if self.__salt is None:
            self.__salt = get_random_bytes(Imprint.NONCE_LEN)
        return self.__salt

    @property
    def as_bytes(self) -> bytes:
        if self.__as_bytes is None:
            self.__as_bytes = \
                blake192(self.private_key.as_bytes, self.nonce) + self.nonce
            assert len(self.__as_bytes) == Imprint.FULL_LEN
        return self.__as_bytes

    @property
    def as_str(self) -> str:
        """Returns the imprint as a string that can be used
        as a filename."""
        if self.__as_str is None:
            self.__as_str = bytes_to_fn_str(self.as_bytes)
        return self.__as_str

    @staticmethod
    def bytes_to_nonce(h: bytes) -> bytes:
        if len(h) != Imprint.FULL_LEN:
            raise ValueError
        return h[-Imprint.NONCE_LEN:]


assert Imprint.FULL_LEN == BASENAME_SIZE


# def pk_matches_codename(pk: FilesetPrivateKey, codename: str) -> bool:
#     try:
#         bts = fnstr_to_bytes(codename)
#     except binascii.Error:
#         return False
#
#     if len(bts) != Imprint.FULL_LEN:
#         return False
#
#     nonce = Imprint.bytes_to_nonce(bts)
#
#     assert len(nonce) == Imprint.NONCE_LEN
#     return codename == Imprint(pk, nonce=nonce).as_str
#
#
def pk_matches_imprint_bytes(pk: FilesetPrivateKey, imprint: bytes) -> bool:
    nonce = Imprint.bytes_to_nonce(imprint)
    return Imprint(pk, nonce=nonce).as_bytes == imprint


class HashCollision(Exception):
    """The program works correctly, based on the assumption that we always get
    different hashes from different data. We also assume that the generated
    nonces never match.

    In theory, both assumptions are wrong. In practice, the chance of getting
    such a collision is much less than the inoperability of the program for
    other reasons."""
    pass
