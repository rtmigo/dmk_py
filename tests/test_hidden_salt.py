import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ksf._00_common import PK_SALT_SIZE, MAX_SALT_FILE_SIZE, InsufficientData
from ksf._00_randoms import get_noncrypt_random_bytes
from ksf.hidden_salt import write_salt, read_salt, NotSaltFilename, \
    SaltVerificationFailed


class TestSalt(unittest.TestCase):

    def test_reads_correct(self):
        with TemporaryDirectory() as tds:
            salt_file = write_salt(Path(tds))
            self.assertTrue(salt_file.exists())
            salt = read_salt(salt_file)
            self.assertIsInstance(salt, bytes)
            self.assertEqual(len(salt), PK_SALT_SIZE)
            self.assertEqual(read_salt(salt_file), salt)

    def test_fails_wrong_fn(self):
        with self.assertRaises(NotSaltFilename):
            read_salt(Path('/tmp/file'))

    def test_fails_verification(self):
        with TemporaryDirectory() as tds:
            salt_file = write_salt(Path(tds))
            size = salt_file.stat().st_size
            salt_file.write_bytes(get_noncrypt_random_bytes(size))
            with self.assertRaises(SaltVerificationFailed):
                read_salt(salt_file)

    def test_fails_insufficient(self):
        with TemporaryDirectory() as tds:
            salt_file = write_salt(Path(tds))
            salt_file.write_bytes(b'123')
            with self.assertRaises(InsufficientData):
                read_salt(salt_file)

    def test_sizes(self):
        sizes = set()
        with TemporaryDirectory() as tds:
            salt_file = write_salt(Path(tds))
            sizes.add(salt_file.stat().st_size)

        self.assertLessEqual(max(sizes), MAX_SALT_FILE_SIZE)
