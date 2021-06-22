# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


from typing import BinaryIO, Tuple

from Crypto.Hash import BLAKE2b, BLAKE2s

KEY_SIZE = 32
assert KEY_SIZE * 8 == 256

# we use salt size value different than the key size, so that we can easily
# distinguish the array with the key from the array with salt when checking
# arguments
KEY_SALT_SIZE = 38

IMPRINT_SIZE = 32

CODENAME_LENGTH_BYTES = 40
HEADER_SIZE = 13

########################

CLUSTER_SIZE = 4096

# all the meta data in block: nonce, header, header checksum.
CLUSTER_META_SIZE = 57

# the maximum amount of data (in bytes) that can be saved in single cluster
MAX_CLUSTER_CONTENT_SIZE = CLUSTER_SIZE - CLUSTER_META_SIZE
assert MAX_CLUSTER_CONTENT_SIZE <= CLUSTER_SIZE


def read_or_fail(f: BinaryIO, n: int) -> bytes:
    result = f.read(n)
    if len(result) != n:
        raise InsufficientData
    return result


class InsufficientData(Exception):
    pass


def half_n_half(salt: bytes) -> Tuple[bytes, bytes]:
    """Splits bytes array in two equal parts (if the array length is even),
    or almost equal (if it's odd)"""
    half = len(salt) >> 1
    a = salt[:half]
    b = salt[half:]
    assert abs(len(a) - len(b)) <= 1
    return a, b


def blake192(data: bytes, salt: bytes) -> bytes:
    # todo remove?
    h_obj = BLAKE2b.new(digest_bits=192)
    a, b = half_n_half(salt)
    h_obj.update(a + data + b)
    return h_obj.digest()


def blake2s_256(data: bytes, salt: bytes) -> bytes:
    h_obj = BLAKE2s.new(digest_bits=256)
    a, b = half_n_half(salt)
    h_obj.update(a + data + b)
    return h_obj.digest()
