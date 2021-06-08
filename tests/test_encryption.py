# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT
import random
import unittest
from base64 import b64encode
from pathlib import Path
from tempfile import TemporaryDirectory

from ksf._20_encryption import _encrypt_file_to_file, encrypt_to_dir, \
    MacCheckFailed, DecryptedFile, name_matches_header
from ksf._randoms import get_fast_random_bytes


class TestEncryptDecrypt(unittest.TestCase):

    def test_name_matches_header(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            source = td / "source"
            source.write_bytes(bytes([77, 88, 99]))

            right = td / "irrelevant"
            NAME = 'abc'
            # name_to_hash(NAME)
            _encrypt_file_to_file(source, NAME, right)
            self.assertTrue(name_matches_header('abc', right))
            self.assertFalse(name_matches_header('def', right))

    def test_encrypted_does_not_contain_plain(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)
            source_file = td / "source"
            body = b'qwertyuiop!qwertyuiop'
            source_file.write_bytes(body)
            encrypted_file = encrypt_to_dir(source_file, 'some_name', td)

            # checking that the original content can be found in original file,
            # but not in the encrypted file
            self.assertIn(body, source_file.read_bytes())

            # the same way we can find original content in the original file
            self.assertNotIn(body, encrypted_file.read_bytes())

    def test_on_random_data(self):
        for _ in range(100):
            name_len = random.randint(1, 99)
            name = b64encode(get_fast_random_bytes(name_len)).decode()

            body_len = random.randint(0, 9999)
            body = get_fast_random_bytes(body_len)
            self._encrypt_decrypt(name, body)

    def _encrypt_decrypt(self, name: str, body: bytes):
        with TemporaryDirectory() as tds:
            td = Path(tds)
            source_file = td / "source"
            source_file.write_bytes(body)

            encrypted_file = encrypt_to_dir(source_file, name, td)

            # checking that the original content can be found in original file,
            # but not in the encrypted file
            self.assertIn(body, source_file.read_bytes())

            # the same way we can find original content in the original file
            self.assertNotIn(body, encrypted_file.read_bytes())

            self.assertTrue(encrypted_file.exists())

            with self.assertRaises(MacCheckFailed):
                DecryptedFile(encrypted_file, 'wrong_item_name')

            df = DecryptedFile(encrypted_file, name)
            self.assertEqual(df.body, body)
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
