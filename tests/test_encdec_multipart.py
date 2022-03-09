# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import io
import random
import unittest
from io import BytesIO
from typing import List, Optional

from dmk._common import MAX_CLUSTER_CONTENT_SIZE
from dmk.a_base._10_kdf import FasterKDF, CodenameKey
from dmk.a_utils.randoms import get_noncrypt_random_bytes
from dmk.b_cryptoblobs import DecryptedIO
from dmk.b_cryptoblobs._30_encdec_multipart import decrypt_from_dios, \
    MultipartEncryptor, split_cluster_sizes
from tests.common import testing_salt


def random_alpha_string(min_len=1, max_len=10) -> str:
    name_len = random.randint(min_len, max_len)
    name = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz')
                   for _ in range(name_len))
    assert len(name) == name_len
    return name


class TestEncryptDecryptFiles(unittest.TestCase):
    faster: FasterKDF

    @classmethod
    def setUpClass(cls) -> None:
        cls.faster = FasterKDF()
        cls.faster.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.faster.end()

    def test_split_cluster_sizes(self):

        sizes = [0, 1,
                 MAX_CLUSTER_CONTENT_SIZE - 1,
                 MAX_CLUSTER_CONTENT_SIZE,
                 MAX_CLUSTER_CONTENT_SIZE + 1]
        for _ in range(1000):
            sizes.append(random.randint(1, 1024 * 1024))

        for s in sizes:
            with self.subTest(f"Size {s}"):
                parts = split_cluster_sizes(s)
                # at least one part
                self.assertGreaterEqual(len(parts), 1)
                # sum match
                self.assertEqual(sum(parts), s)
                # it's only 1 or 2 lengths
                self.assertLessEqual(len(set(parts)), 2)
                self.assertGreaterEqual(len(set(parts)), 1)
                # each not larger than allowed size
                for p in parts:
                    self.assertGreaterEqual(p, 0)
                    self.assertLessEqual(p, MAX_CLUSTER_CONTENT_SIZE)
                # if zero, it is the only element
                if 0 in parts:
                    self.assertEqual(len(parts), 1)

    def test_encdec_empty(self):
        self._encrypt_decrypt('name', b'')

    def test_encdec_random(self):
        for _ in range(10):
            name = random_alpha_string(0, 10)

            #
            full_data_len = random.randint(0, 1024 * 128)
            full_data = get_noncrypt_random_bytes(full_data_len)

            self._encrypt_decrypt(name, full_data)

    def _encrypt_decrypt(self, name: str, body: bytes):

        fpk = CodenameKey(name, testing_salt)

        encrypted_parts: List[bytes] = []

        with BytesIO(body) as original_io:
            me = MultipartEncryptor(fpk, original_io, content_version=5)

            # when encrypting data, we take the parts in random order.
            # Thus, we check that sequential reading of the original
            # stream is not necessary
            part_indexes = list(range(len(me.part_sizes)))
            random.shuffle(part_indexes)

            for idx in part_indexes:
                with BytesIO() as output_io:
                    self.assertFalse(me.all_encrypted)
                    me.encrypt(idx, output_io)
                    output_io.seek(0, io.SEEK_SET)
                    encrypted_parts.append(output_io.read())
            self.assertTrue(me.all_encrypted)

        decrypted_parts: Optional[List[DecryptedIO]] = None
        try:
            decrypted_parts = [DecryptedIO(fpk, BytesIO(buf))
                               for buf in encrypted_parts]
            random.shuffle(decrypted_parts)
            with BytesIO() as decrypted_full_io:
                decrypt_from_dios(decrypted_parts, decrypted_full_io)
                decrypted_full_io.seek(0)
                decrypted_full_bytes = decrypted_full_io.read()
            self.assertEqual(decrypted_full_bytes, body)

            # print(f"yeah? {len(decrypted_full_bytes)}")
        finally:
            if decrypted_parts:
                for s in decrypted_parts:
                    s._source.close()


if __name__ == "__main__":
    # TestEncryptDecryptFiles().test_encdec_random()
    unittest.main()
    # TestEncryptDecrypt()._encrypt_decrypt('abcdef', b'qwertyuiop',
    #                                     check_wrong=False)
    # print("OK")
