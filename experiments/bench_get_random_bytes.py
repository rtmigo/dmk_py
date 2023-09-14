from timeit import timeit

from Crypto.Random import get_random_bytes

from dmk.a_utils.randoms import get_noncrypt_random_bytes

size = 1024 * 1024


def get_urandom():
    get_random_bytes(size)


import random


def bench_randbytes():
    get_noncrypt_random_bytes(size)


def bytes_from_randbits():
    return bytes(random.getrandbits(8) for _ in range(size))


def bytes_from_ints():
    return bytes(random.randint(0, 0xFF) for _ in range(size))


if __name__ == "__main__":
    N = 5
    for _ in range(5):
        print(f"urandom {timeit(get_urandom, number=N):.2f}")
        print(
            f"bytes_from_randbits {timeit(bytes_from_randbits, number=N):.2f}")
        print(
            f"bench_randbytes {timeit(bench_randbytes, number=N):.2f}")
    print("done")
