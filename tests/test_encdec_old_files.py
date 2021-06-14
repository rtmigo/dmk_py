# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import random
import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from codn.cryptodir._10_kdf import FasterKDF, CodenameKey
from codn.cryptodir.namegroup import DecryptedIO
from codn.cryptodir.namegroup.encdec._26_encdec_full import encrypt_to_files, \
    decrypt_from_dios, split_random_sizes
from codn.utils.randoms import get_noncrypt_random_bytes
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

    def test_split_random_sizes(self):
        N = 999999
        a = split_random_sizes(N)
        b = split_random_sizes(N)
        self.assertEqual(a, a.copy())
        self.assertNotEqual(a, b)

    def test_split_random_sizes_zero(self):
        self.assertEqual(split_random_sizes(0), [0])



    def test_encdec_empty(self):
        self._encrypt_decrypt('name', b'')

    # # @unittest.skip('temp')
    def test_encdec_random(self):
        for _ in range(10):
            name = random_alpha_string(0, 10)

            #
            full_data_len = random.randint(0, 1024 * 128)
            full_data = get_noncrypt_random_bytes(full_data_len)

            self._encrypt_decrypt(name, full_data)

    #
    #         if full_original_len > 0:
    #             part_pos = random.randint(0, full_original_len - 1)
    #         else:
    #             part_pos = 0
    #         part_max_size = full_original_len - part_pos
    #         part_size = random.randint(0, part_max_size)
    #         assert part_pos + part_size <= full_original_len
    #
    #         parts_len = random.randint(1, 10)
    #         part_idx = random.randint(0, parts_len - 1)
    #
    #         self._encrypt_decrypt(name,
    #                               full_original,
    #                               pos=part_pos,
    #                               parts_len=parts_len,
    #                               part_size=part_size,
    #                               part_idx=part_idx)

    def _encrypt_decrypt(self,
                         name: str,
                         body: bytes):
        # print(f"ENCDEC: parts_len={parts_len}")
        # print(f"ENCDEC: part_idx={part_idx}")
        # print(f"ENCDEC: part_size={part_size}")

        with TemporaryDirectory() as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            fpk = CodenameKey(name, testing_salt)
            with BytesIO(body) as original_io:
                files = encrypt_to_files(fpk, original_io, temp_dir,
                                         content_version=1)

            try:
                decrypted_parts = [DecryptedIO(fpk, f.open('rb'))
                                   for f in files]
                random.shuffle(decrypted_parts)
                with BytesIO() as decrypted_full_io:
                    decrypt_from_dios(decrypted_parts, decrypted_full_io)
                    decrypted_full_io.seek(0)
                    decrypted_full_bytes = decrypted_full_io.read()
                self.assertEqual(decrypted_full_bytes, body)
                # print(f"yeah? {len(decrypted_full_bytes)}")
            finally:
                for s in decrypted_parts:
                    s.source.close()

        #
        #
        # fpk = FilesetPrivateKey(name, testing_salt)
        #
        # with BytesIO(body) as original_io:
        #     original_io.seek(pos)
        #     with BytesIO() as encrypted_io:
        #         Encrypt(fpk,
        #                 parts_len=parts_len,
        #                 part_idx=part_idx,
        #                 part_size=part_size) \
        #             .io_to_io(original_io, encrypted_io)
        #         encrypted_io.seek(0)
        #         encrypted = encrypted_io.read()
        #
        # # checking that the original content can be found in original file,
        # # but not in the encrypted file
        # self.assertIn(expected_part_content, body)
        # if len(expected_part_content) > 6:
        #     self.assertNotIn(expected_part_content, encrypted)
        #
        # # checking the we cannot decrypt the data with wrong key
        # if check_wrong:
        #     with self.assertRaises(GroupImprintMismatch):
        #         wrong_key = FilesetPrivateKey('WrOnG', testing_salt)
        #         with BytesIO(encrypted) as input_io:
        #             DecryptedIO(wrong_key, input_io).read_data()
        #
        # with BytesIO(encrypted) as input_io:
        #     df = DecryptedIO(fpk, input_io)
        #     self.assertEqual(df.header.data_size, len(body))
        #     self.assertEqual(df.header.part_idx, part_idx)
        #     self.assertEqual(df.header.parts_len, parts_len)
        #     if part_size is not None:
        #         self.assertEqual(df.header.part_size, part_size)
        #     else:
        #         self.assertEqual(df.header.part_size, len(body))
        #
        #     decrypted_part_content = df.read_data()
        #     self.assertEqual(decrypted_part_content, expected_part_content)
        #
        # return decrypted_part_content


if __name__ == "__main__":
    # TestEncryptDecryptFiles().test_encdec_random()
    unittest.main()
    # TestEncryptDecrypt()._encrypt_decrypt('abcdef', b'qwertyuiop',
    #                                     check_wrong=False)
    # print("OK")
