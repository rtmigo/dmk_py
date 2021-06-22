from timeit import timeit

from Crypto.Hash import BLAKE2b
from Crypto.Random import get_random_bytes

DATA = b'1234567890' * 1000000

KEY = get_random_bytes(32)
NONCE = get_random_bytes(12)


def blake2_256():
    h_obj = BLAKE2b.new(digest_bits=256)
    h_obj.update(DATA)
    return h_obj.digest()


def blake2_128():
    h_obj = BLAKE2b.new(digest_bits=128)
    h_obj.update(DATA)
    return h_obj.digest()


if __name__ == "__main__":
    # blake2 speed does not depend on digest size

    N = 50
    for _ in range(5):
        print("blake2_256", timeit(blake2_256, number=N))
        print("blake2_128", timeit(blake2_128, number=N))
    print("done")
