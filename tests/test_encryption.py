# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import random
import unittest
from base64 import b64encode
from pathlib import Path
from tempfile import TemporaryDirectory

from ksf._00_randoms import get_fast_random_bytes
from ksf._20_key_derivation import FasterKeys, FilesetPrivateKey
from ksf._61_encryption import _encrypt_file_to_file, encrypt_to_dir, \
    ChecksumMismatch, DecryptedFile, pk_matches_header


class TestEncryptDecrypt(unittest.TestCase):
    faster: FasterKeys

    @classmethod
    def setUpClass(cls) -> None:
        cls.faster = FasterKeys()
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
            _encrypt_file_to_file(source, FilesetPrivateKey(NAME), right)
            self.assertTrue(pk_matches_header(FilesetPrivateKey(NAME), right))
            self.assertFalse(
                pk_matches_header(FilesetPrivateKey('labuda'), right))

    def test_encrypted_does_not_contain_plain(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)
            source_file = td / "source"
            body = b'qwertyuiop!qwertyuiop'
            source_file.write_bytes(body)
            encrypted_file = encrypt_to_dir(source_file,
                                            FilesetPrivateKey('some_name'), td)

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

            fpk = FilesetPrivateKey('some_name')

            files = [encrypt_to_dir(source_file, fpk, td)
                     for _ in range(10)]

            self.assertEqual(len(set(str(f) for f in files)), 10)

            sizes = set([f.stat().st_size for f in files])
            print(sizes)
            self.assertGreater(len(sizes), 3)

    def test_on_random_data(self):
        for _ in range(100):
            name_len = random.randint(1, 99)
            name = b64encode(get_fast_random_bytes(name_len)).decode()

            body_len = random.randint(0, 9999)
            body = get_fast_random_bytes(body_len)
            self._encrypt_decrypt(name, body)

    def _encrypt_decrypt(self, name: str, body: bytes, check_wrong=False):
        with TemporaryDirectory() as tds:
            td = Path(tds)
            source_file = td / "source"
            source_file.write_bytes(body)

            fpk = FilesetPrivateKey(name)

            encrypted_file = encrypt_to_dir(source_file, fpk, td)

            # checking that the original content can be found in original file,
            # but not in the encrypted file
            self.assertIn(body, source_file.read_bytes())

            # the same way we can find original content in the original file
            self.assertNotIn(body, encrypted_file.read_bytes())

            self.assertTrue(encrypted_file.exists())

            if check_wrong:
                with self.assertRaises(ChecksumMismatch):
                    DecryptedFile(encrypted_file,
                                  FilesetPrivateKey('wrong_item_name'))

            df = DecryptedFile(encrypted_file, fpk)
            self.assertEqual(df.data, body)
            self.assertEqual(df.mtime, source_file.stat().st_mtime)

            # writing the decrypted data to disk checking the saved file is
            # the same as the original

            decrypted_file = td / "dec"
            self.assertFalse(decrypted_file.exists())
            df.write(decrypted_file)
            self.assertTrue(decrypted_file.exists())
            self.assertEqual(decrypted_file.read_bytes(), body)
            self.assertEqual(decrypted_file.stat().st_mtime,
                             source_file.stat().st_mtime)

    def test_decrypt_header_only(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)
            source_file = td / "source"
            source_file.write_bytes(b'abc')
            NAME = "thename"
            pk = FilesetPrivateKey(NAME)
            encrypted_file = encrypt_to_dir(source_file, pk, td)
            df = DecryptedFile(encrypted_file, pk, decrypt_body=False)

            # meta-data is loaded
            self.assertEqual(df.size, source_file.stat().st_size)
            # but there is no body
            self.assertEqual(df.data, None)





if __name__ == "__main__":
    unittest.main()
    # TestEncryptDecrypt()._encrypt_decrypt('abcdef', b'qwertyuiop',
    #                                     check_wrong=False)
    # print("OK")
