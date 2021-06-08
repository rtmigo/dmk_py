import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ksf._20_encryption import _encrypt_file_to_file, encrypt_to_dir, \
    MacCheckFailed, DecryptedFile, name_matches_header, IntroPadding


class TestEncryptDecrypt(unittest.TestCase):

        #minn =

        #for _ in range(500):
        #    padding = intro_padding()
        #    size = len(padding)
        #    #self.assertGreaterEqual(size, 0)
        #    #self.assertLess([], 15)

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

    def test(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)
            source_file = td / "source"
            body = b'qwertyuiop'
            source_file.write_bytes(body)

            NAME = "my_item_name"

            encrypted_file = encrypt_to_dir(source_file, NAME, td)

            # checking that the original content can be found in original file,
            # but not in the encrypted file
            self.assertIn(body, source_file.read_bytes())

            # the same way we can find original content in the original file
            self.assertNotIn(body, encrypted_file.read_bytes())

            self.assertTrue(encrypted_file.exists())

            with self.assertRaises(MacCheckFailed):
                DecryptedFile(encrypted_file, 'wrong_item_name')

            df = DecryptedFile(encrypted_file, NAME)
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
