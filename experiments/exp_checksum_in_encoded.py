"""
We compare the number of false checksum matches: if it is part of the encrypted
data, and if not.

If the checksum is itself inside the encrypted message, it would seem that we
need to correctly decrypt not only the message, but also the sum. This will
be a tougher test.

But an experiment shows that this is an illusion. Our checksum is as much as
a third of the decrypted data. The number of false matches is
0.0039 (1/256) anyway.
"""

import zlib

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

DATA = bytes((11, 22))
CORRECT_KEY = get_random_bytes(32)


def one_byte_checksum(data: bytes) -> bytes:
    # one-byte checksum
    return bytes((zlib.crc32(data) & 0xFF,))


def encrypt_correct_key(data: bytes) -> bytes:
    cipher = ChaCha20.new(key=CORRECT_KEY)
    return cipher.encrypt(data)


def decrypt_wrong_key(data):
    wrong_key = get_random_bytes(32)
    assert wrong_key != CORRECT_KEY
    cipher = ChaCha20.new(key=wrong_key)
    return cipher.decrypt(data)


N = 1000000


def test_checksum_outside():
    checksum = one_byte_checksum(DATA)
    encrypted = encrypt_correct_key(DATA)

    false_matches = 0
    for _ in range(N):
        decrypted = decrypt_wrong_key(encrypted)
        if one_byte_checksum(decrypted) == checksum:
            false_matches += 1

    print(f"Outside: {false_matches * 100 / N:.3f}%")


def test_checksum_inside():
    # checksum is also encrypted
    # (so we need to decrypt correctly both message and checksum
    # to get the match)
    checksum = one_byte_checksum(DATA)
    encrypted = encrypt_correct_key(DATA + checksum)

    false_matches = 0
    for _ in range(N):
        decrypted = decrypt_wrong_key(encrypted)
        decrypted_msg = decrypted[:-1]
        decrypted_checksum = decrypted[-1:]
        if one_byte_checksum(decrypted_msg) == decrypted_checksum:
            false_matches += 1

    print(f"Inside: {false_matches * 100 / N:.3f}%")


if __name__ == "__main__":
    # Outside: 0.394%
    # Inside: 0.391%
    test_checksum_outside()
    test_checksum_inside()
