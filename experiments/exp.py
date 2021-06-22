"""Testing a not entirely obvious statement.

Two ways to do the same thing:

1) Store a string constant inside an encrypted stream (without verification).
   Decrypt it and compare it with the original constant - make sure
   constants equal

2) Compare hashes to make sure the original constants are identical

The first method can easily lead to an error: we are decrypting the
constant incorrectly, but we will take it as correct.

The second one much more reliable.
"""

from Crypto.Cipher import ChaCha20
from Crypto.Hash import BLAKE2b
from Crypto.Random import get_random_bytes


def blake_256(data):
    h_obj = BLAKE2b.new(digest_bits=256)
    h_obj.update(data)
    return h_obj.digest()


def gen_key_256():
    return get_random_bytes(32)


def gen_nonce_96():
    return get_random_bytes(12)


def encrypt_chacha(key, data: bytes) -> bytes:
    cipher = ChaCha20.new(key=key, nonce=gen_nonce_96())
    return cipher.encrypt(data)


N = 1000000


def find_chacha_collision():
    """In this example, we encrypt A, but after decrypting (with a different
    key!) we get B.

    In fact, randomly generating a nonce is like brute-forcing a situation
    where such a false match will occur.

    Verification of the decrypted stream would correct the situation. But
    verification is also not completely deterministic and relies on hashes.
    The question is, why then encrypt the string, if it was possible to
    just compare hashes.
    """
    key_a = gen_key_256()

    data_a = encrypt_chacha(key_a, b'A')

    key_b = gen_key_256()
    assert key_b != key_a
    for i in range(N):
        if decrypt_chacha(key_b, data_a, gen_nonce_96()) == b'B':
            print(f"Found ChaCha collision on step {i}")
            return

    print(f"ChaCha collision not found")


def find_blake_collision(salt_size: int):
    salt_a = get_random_bytes(salt_size)
    hash_a = blake_256(b'A' + salt_a)

    for i in range(N):
        salt_b = get_random_bytes(salt_size)
        hash_b = blake_256(b'B' + salt_b)

        if hash_a == hash_b:
            print(f"Found Blake collision on step {i} (salt size: {salt_size})")
            return

    print(f"Blake collision not found (salt size: {salt_size})")


def decrypt_chacha(key, data, nonce):
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(data)


if __name__ == "__main__":
    find_chacha_collision()
    find_blake_collision(12)
    find_blake_collision(1)
    pass
    # N = 50000
    # for _ in range(5):
    #     print("blake", timeit(blake2, number=N))
    #     print("chacha", timeit(decrypt_chacha, number=N))
    # print("done")
