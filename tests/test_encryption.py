# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import random
import unittest
from base64 import b64encode
from pathlib import Path
from tempfile import TemporaryDirectory

from ksf._00_common import MIN_DATA_FILE_SIZE
from ksf._00_randoms import get_noncrypt_random_bytes
from ksf._20_kdf import FasterKDF, FilesetPrivateKey
from ksf._61_encryption import Encrypt, encrypt_to_dir, \
    ChecksumMismatch, _DecryptedFile, fpk_matches_header
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

    def test_name_matches_header(self):

        with TemporaryDirectory() as tds:
            td = Path(tds)

            source = td / "source"
            source.write_bytes(bytes([77, 88, 99]))

            right = td / "irrelevant"
            NAME = 'abc'
            # name_to_hash(NAME)
            Encrypt(FilesetPrivateKey(NAME, testing_salt)).file_to_file(source, right)
            self.assertTrue(fpk_matches_header(FilesetPrivateKey(NAME, testing_salt), right))
            self.assertFalse(
                fpk_matches_header(FilesetPrivateKey('labuda', testing_salt), right))

    def test_encrypted_does_not_contain_plain(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)
            source_file = td / "source"
            body = b'qwertyuiop!qwertyuiop'
            source_file.write_bytes(body)
            encrypted_file = encrypt_to_dir(source_file,
                                            FilesetPrivateKey('some_name', testing_salt), td)

            # checking that the original content can be found in original file,
            # but not in the encrypted file
            self.assertIn(body, source_file.read_bytes())

            # the same way we can find original content in the original file
            self.assertNotIn(body, encrypted_file.read_bytes())

    def test_encrypted_files_have_different_sizes_plain(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)
            source_file = td / "source"
            body = b'qwertyuiop!qwertyuiop'
            source_file.write_bytes(body)

            fpk = FilesetPrivateKey('some_name', testing_salt)

            files = [encrypt_to_dir(source_file, fpk, td)
                     for _ in range(10)]

            self.assertEqual(len(set(str(f) for f in files)), 10)

            sizes = set([f.stat().st_size for f in files])
            # at least three different file sizes
            self.assertGreater(len(sizes), 3)
            self.assertTrue(all(x >= MIN_DATA_FILE_SIZE for x in sizes))

    def test_on_random_data(self):
        random.seed(55, version=2)
        for _ in range(100):
            name_len = random.randint(1, 99)
            name = b64encode(get_noncrypt_random_bytes(name_len)).decode()

            body_len = random.randint(0, 9999)
            body = get_noncrypt_random_bytes(body_len)
            self._encrypt_decrypt(name, body)

    def _encrypt_decrypt(self, name: str, body: bytes, check_wrong=False):
        with TemporaryDirectory() as tds:
            td = Path(tds)
            source_file = td / "source"
            source_file.write_bytes(body)

            fpk = FilesetPrivateKey(name, testing_salt)

            encrypted_file = encrypt_to_dir(source_file, fpk, td)

            # checking that the original content can be found in original file,
            # but not in the encrypted file
            self.assertIn(body, source_file.read_bytes())

            # the same way we can find original content in the original file
            self.assertNotIn(body, encrypted_file.read_bytes())

            self.assertTrue(encrypted_file.exists())

            if check_wrong:
                with self.assertRaises(ChecksumMismatch):
                    _DecryptedFile(encrypted_file,
                                   FilesetPrivateKey('wrong_item_name', testing_salt))

            df = _DecryptedFile(encrypted_file, fpk)
            self.assertEqual(df.data, body)
            # №self.assertEqual(df.mtime, source_file.stat().st_mtime)

            # writing the decrypted data to disk checking the saved file is
            # the same as the original

            decrypted_file = td / "dec"
            self.assertFalse(decrypted_file.exists())
            df.write(decrypted_file)
            self.assertTrue(decrypted_file.exists())
            self.assertEqual(decrypted_file.read_bytes(), body)
            # self.assertEqual(decrypted_file.stat().st_mtime,
            #                  source_file.stat().st_mtime)

    def test_decrypt_header_only(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)
            source_file = td / "source"
            source_file.write_bytes(b'abc')
            NAME = "thename"
            pk = FilesetPrivateKey(NAME, testing_salt)
            encrypted_file = encrypt_to_dir(source_file, pk, td)
            df = _DecryptedFile(encrypted_file, pk, decrypt_body=False)

            # meta-data is loaded
            self.assertEqual(df.size, source_file.stat().st_size)
            # but there is no body
            self.assertEqual(df.data, None)


if __name__ == "__main__":
    unittest.main()
    # TestEncryptDecrypt()._encrypt_decrypt('abcdef', b'qwertyuiop',
    #                                     check_wrong=False)
    # print("OK")
