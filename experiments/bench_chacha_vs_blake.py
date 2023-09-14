from timeit import timeit

from Crypto.Cipher import ChaCha20
from Crypto.Hash import BLAKE2b
from Crypto.Random import get_random_bytes

DATA = b'123456789012345678901234567890123456789' \
       b'01234567890123456789012345678901234567890'

KEY = get_random_bytes(32)
NONCE = get_random_bytes(12)


def blake2():
    h_obj = BLAKE2b.new(digest_bits=256)
    h_obj.update(DATA)
    return h_obj.digest()


def encryptChaCha20(data: bytes) -> bytes:
    cipher = ChaCha20.new(key=KEY, nonce=NONCE)
    return cipher.encrypt(data)


ENCRYPTED = encryptChaCha20(DATA)


def decrypt_chacha():
    cipher = ChaCha20.new(key=KEY, nonce=NONCE)
    cipher.decrypt(ENCRYPTED)


if __name__ == "__main__":
    N = 50
    for _ in range(5):
        print("blake", timeit(blake2, number=N))
        print("chacha", timeit(decrypt_chacha, number=N))
    print("done")
