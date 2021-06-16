# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

from typing import Optional

from Crypto.Random import get_random_bytes

from codn._common import bytes_to_fn_str, blake192,  blake256
from codn.a_base._10_kdf import CodenameKey




class Imprint:
    """Each codename key (CK) has a conventionally infinite number of imprints
    (2^192 or six octodecillion).

    Each new imprint is unique, although the key is the same.

    Knowing the key, we can tell if the imprint belongs to it.

    Without knowing the CK, we can hardly do anything. We cannot
    reconstruct a CK from an imprint, or even suggest it. We cannot say
    whether two imprints correspond to the same CK or to different ones.

    ==

    Imprint collision can happen in two ways:
    - we will generate two identical imprints for the same name
    - different names will produce the same imprints

    Until we're in a spaceship with infinite improbability drive,
    neither will happen.
    """

    __slots__ = ['__private_key', '__salt', '__as_bytes', '__as_str']

    NONCE_LEN = 32
    DIGEST_LEN = 32
    FULL_LEN = NONCE_LEN + DIGEST_LEN

    def __init__(self, pk: CodenameKey, nonce: bytes = None):
        if not isinstance(pk, CodenameKey):
            raise TypeError
        self.__private_key = pk
        self.__salt: Optional[bytes] = nonce
        self.__as_bytes: Optional[bytes] = None
        self.__as_str: Optional[str] = None

    @property
    def private_key(self) -> CodenameKey:
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
                blake256(self.private_key.as_bytes, self.nonce) + self.nonce
            assert len(self.__as_bytes) == Imprint.FULL_LEN, \
                f"len={len(self.__as_bytes)}"
        return self.__as_bytes

    @property
    def as_str(self) -> str:
        """Returns the imprint as a string that can be used
        as a filename."""
        # unused
        if self.__as_str is None:
            self.__as_str = bytes_to_fn_str(self.as_bytes)
        return self.__as_str

    @staticmethod
    def bytes_to_nonce(h: bytes) -> bytes:
        if len(h) != Imprint.FULL_LEN:
            raise ValueError
        return h[-Imprint.NONCE_LEN:]


#assert Imprint.FULL_LEN == BASENAME_SIZE


def pk_matches_imprint_bytes(pk: CodenameKey, imprint: bytes) -> bool:
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
