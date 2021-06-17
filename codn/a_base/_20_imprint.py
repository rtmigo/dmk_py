# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

from typing import Optional

from Crypto.Random import get_random_bytes

from codn._common import bytes_to_fn_str, blake256
from codn.a_base._10_kdf import CodenameKey


class Imprint:
    """Each codename key (CK) has a conventionally infinite number of imprints.

    ===

    Different nonce values allow us to generate different imprints for
    the same private key.

    Hashes allow us to identify blocks that are (probably) associated with
    this private key.


    IMPRINT COLLISION
    -----------------

    False imprint matches are possible in the following cases:

    1. KDF failure: KDF produces two identical keys from different codenames,
       so both codenames consider blocks as their own

    2. URandom failure: Two identical nonces are used for the same private
       key (same codename), so we got totally identical imprints for two
       different blocks

    3. Blake2 failure: With the same nonce, but different private keys,
       the function produced the same hash

    4. Some of these problems happened at the same time.

    All of these incredible coincidences reveal more data than we planned.
    However, no attacker will exploit this. Even iterating over keys for a
    thousand years is more efficient than waiting in full readiness for a
    random, not very useful collision.

    It is important that the utility does not corrupt the data due to
    a collision.

    The good news is that an imprint collision will only make us briefly
    think that some block belongs to the current name group, although it isn't.
    Next, we will read the encrypted block header, which stores the original
    codename. Only after verifying the header, we will make a final conclusion
    about what we are dealing with.

    The bad news is that even the header check is not completely deterministic.
    Since we generate a new (random!) the nonce value before encrypting the
    block, hypothetically there may be a nonce value, that causes completely
    random data to be mistakenly decrypted as a header containing the codename.

    But if this happens, we are on a spaceship with infinite improbability
    drive. This is also not a completely deterministic statement.

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
            self.__salt = self.create_unique_nonce()
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

    @classmethod
    def create_unique_nonce(cls) -> bytes:
        while True:
            result = get_random_bytes(Imprint.NONCE_LEN)
            if result not in cls._known_nonces:
                break

        cls._known_nonces.add(result)
        return result

    @classmethod
    def add_known_nonce(cls, nonce: bytes):

        # todo how to test it?
        if len(nonce) != Imprint.NONCE_LEN:
            raise ValueError
        cls._known_nonces.add(nonce)

    _known_nonces = set()


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
