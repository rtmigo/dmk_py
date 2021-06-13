# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import random
import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from codn.cryptodir._10_kdf import FasterKDF, FilesetPrivateKey
from codn.cryptodir.namegroup.encdec._25_encdec_part import Encrypt, \
    is_content, DecryptedIO, GroupImprintMismatch
from codn.utils.randoms import get_noncrypt_random_bytes
from tests.common import testing_salt


class TestEncryptDecrypt(unittest.TestCase):
    faster: FasterKDF

    @classmethod
    def setUpClass(cls) -> None:
        cls.faster = FasterKDF()
        cls.faster.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.faster.end()

    def test_imprint_match(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            source = td / "source"
            source.write_bytes(bytes([77, 88, 99]))

            right = td / "irrelevant"
            NAME = 'abc'
            # name_to_hash(NAME)
            Encrypt(FilesetPrivateKey(NAME, testing_salt)) \
                .file_to_file(source, right)
            self.assertTrue(
                is_content(FilesetPrivateKey(NAME, testing_salt),
                           right))
            self.assertFalse(
                is_content(FilesetPrivateKey('labuda', testing_salt),
                           right))

    def test_encdec_constant(self):
        self._encrypt_decrypt('name', b'qwertyuiop!qwertyuiop')

    def test_encdec_empty_data(self):
        self._encrypt_decrypt('empty', b'')

    def test_encdec_part(self):
        dec = self._encrypt_decrypt('name', b'0123abc000',
                                    pos=4,
                                    parts_len=5,
                                    part_size=3,
                                    part_idx=2)
        self.assertEqual(dec, b'abc')

    def test_encdec_part_sized_0(self):
        dec = self._encrypt_decrypt('name', b'0123abc000',
                                    pos=4,
                                    parts_len=5,
                                    part_size=0,
                                    part_idx=2)
        self.assertEqual(dec, b'')

    # @unittest.skip('temp')
    def test_encdec_part_random(self):
        for _ in range(1000):
            name_len = random.randint(0, 10)
            name = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz')
                           for _ in range(name_len))
            assert len(name) == name_len

            full_original_len = random.randint(0, 2048)
            full_original = get_noncrypt_random_bytes(full_original_len)

            if full_original_len > 0:
                part_pos = random.randint(0, full_original_len - 1)
            else:
                part_pos = 0
            part_max_size = full_original_len - part_pos
            part_size = random.randint(0, part_max_size)
            assert part_pos + part_size <= full_original_len

            parts_len = random.randint(1, 10)
            part_idx = random.randint(0, parts_len - 1)

            self._encrypt_decrypt(name,
                                  full_original,
                                  pos=part_pos,
                                  parts_len=parts_len,
                                  part_size=part_size,
                                  part_idx=part_idx)

    def _encrypt_decrypt(self,
                         name: str,
                         body: bytes,

                         pos=0,

                         parts_len=1,
                         part_idx=0,
                         part_size=None,

                         check_wrong=True):

        # print(f"ENCDEC: parts_len={parts_len}")
        # print(f"ENCDEC: part_idx={part_idx}")
        # print(f"ENCDEC: part_size={part_size}")

        if part_size is not None:
            expected_part_content = body[pos:pos + part_size]
        else:
            expected_part_content = body

        fpk = FilesetPrivateKey(name, testing_salt)

        with BytesIO(body) as original_io:
            original_io.seek(pos)
            with BytesIO() as encrypted_io:
                Encrypt(fpk,
                        parts_len=parts_len,
                        part_idx=part_idx,
                        part_size=part_size) \
                    .io_to_io(original_io, encrypted_io)
                encrypted_io.seek(0)
                encrypted = encrypted_io.read()

        # checking that the original content can be found in original file,
        # but not in the encrypted file
        self.assertIn(expected_part_content, body)
        if len(expected_part_content) > 6:
            self.assertNotIn(expected_part_content, encrypted)

        # checking the we cannot decrypt the data with wrong key
        if check_wrong:
            with self.assertRaises(GroupImprintMismatch):
                wrong_key = FilesetPrivateKey('WrOnG', testing_salt)
                with BytesIO(encrypted) as input_io:
                    DecryptedIO(wrong_key, input_io).read_data()

        with BytesIO(encrypted) as input_io:
            df = DecryptedIO(fpk, input_io)
            self.assertEqual(df.header.data_size, len(body))
            self.assertEqual(df.header.part_idx, part_idx)
            self.assertEqual(df.header.parts_len, parts_len)
            if part_size is not None:
                self.assertEqual(df.header.part_size, part_size)
            else:
                self.assertEqual(df.header.part_size, len(body))

            decrypted_part_content = df.read_data()
            self.assertEqual(decrypted_part_content, expected_part_content)

        return decrypted_part_content


if __name__ == "__main__":
    unittest.main()
    # TestEncryptDecrypt()._encrypt_decrypt('abcdef', b'qwertyuiop',
    #                                     check_wrong=False)
    # print("OK")
