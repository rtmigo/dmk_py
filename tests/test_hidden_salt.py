import random
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ksf._00_common import PK_SALT_SIZE, MAX_SALT_FILE_SIZE, InsufficientData, \
    BASENAME_SIZE, bytes_to_fn_str
from ksf._00_randoms import get_noncrypt_random_bytes
from ksf.hidden_salt import write_salt, read_salt, NotSaltFilename, \
    SaltVerificationFailed, iter_salts_in_dir


class TestSaltFile(unittest.TestCase):

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


class TestSaltsInDir(unittest.TestCase):

    def test(self):

        def random_file_name():
            if random.randint(0, 1) == 0:
                return bytes_to_fn_str(get_noncrypt_random_bytes(BASENAME_SIZE))
            else:
                return bytes_to_fn_str(get_noncrypt_random_bytes(2))

        def random_file_content():
            return get_noncrypt_random_bytes(
                random.randint(0, MAX_SALT_FILE_SIZE + 1000))

        with TemporaryDirectory() as tds:
            td = Path(tds)
            write_salt(Path(tds))
            for _ in range(100):
                fn = random_file_name()
                (td / fn).write_bytes(random_file_content())

            salts = list(iter_salts_in_dir(td))

        self.assertEqual(len(salts), 1)
        salt = salts[0]
        self.assertIsInstance(salt, bytes)
        self.assertEqual(len(salt), PK_SALT_SIZE)
