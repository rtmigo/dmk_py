import random


def get_fast_random_bytes(n: int):
    return bytes(random.getrandbits(8) for _ in range(n))


