# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import datetime
import random
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from codn._common import PK_SALT_SIZE, MAX_SALT_FILE_SIZE, InsufficientData, \
    unique_filename
from codn.cryptodir._10_salt import write_salt_and_fakes, read_salt, \
    SaltFileBadName, \
    SaltFileTooLarge, find_salt_in_dir, SaltFileIsNotFile, \
    _random_byte_with_lowest_bit_on
from codn.utils.randoms import get_noncrypt_random_bytes


class TestSaltFile(unittest.TestCase):

    def test_random_byte_with_bit(self):
        values = set(_random_byte_with_lowest_bit_on() for _ in range(100))
        self.assertGreater(len(values), 10)
        self.assertTrue(all(b & 1 for b in values))

    def test_reads_correct(self):
        with TemporaryDirectory() as tds:
            sf = write_salt_and_fakes(Path(tds))
            self.assertTrue(sf.file.exists())
            salt = read_salt(sf.file)
            self.assertIsInstance(salt, bytes)
            self.assertEqual(len(salt), PK_SALT_SIZE)
            self.assertEqual(read_salt(sf.file), salt)

    def test_fakes_different_dates(self):
        with TemporaryDirectory() as tds:
            sf = write_salt_and_fakes(Path(tds), min_fakes=10, max_fakes=12)

            dates = set()
            for f in [sf.file] + sf.fakes:
                dates.add(
                    datetime.date.fromtimestamp(f.stat().st_mtime))
        self.assertGreater(len(dates), 4)

    def test_fails_wrong_fn(self):
        with self.assertRaises(SaltFileBadName):
            read_salt(Path('/tmp/.file'))
        with self.assertRaises(SaltFileBadName):
            read_salt(Path('/tmp/thumbs.db'))

    def test_fails_if_not_file(self):
        with TemporaryDirectory() as tds:
            sub = Path(tds) / "nameok1"
            with self.assertRaises(FileNotFoundError):
                read_salt(sub)
            sub.mkdir()
            with self.assertRaises(SaltFileIsNotFile):
                read_salt(sub)

    # def test_fails_too_large(self):
    #     with TemporaryDirectory() as tds:
    #         salt_file = write_salt(Path(tds))
    #         size = salt_file.stat().st_size
    #         salt_file.write_bytes(get_noncrypt_random_bytes(size))
    #         with self.assertRaises(SaltVerificationFailed):
    #             read_salt(salt_file)

    def test_fails_too_large(self):
        with TemporaryDirectory() as tds:
            sf = write_salt_and_fakes(Path(tds))
            sf.file.write_bytes(b'1' * (MAX_SALT_FILE_SIZE + 1))
            with self.assertRaises(SaltFileTooLarge):
                read_salt(sf.file)

    def test_fails_insufficient(self):
        with TemporaryDirectory() as tds:
            sf = write_salt_and_fakes(Path(tds))
            sf.file.write_bytes(b'123')
            with self.assertRaises(InsufficientData):
                read_salt(sf.file)

    def test_sizes(self):
        sizes = set()
        with TemporaryDirectory() as tds:
            sf = write_salt_and_fakes(Path(tds))
            sizes.add(sf.file.stat().st_size)

        self.assertLessEqual(max(sizes), MAX_SALT_FILE_SIZE)


class TestSaltsInDir(unittest.TestCase):

    def test(self):
        def random_file_content(min_size, max_size):
            return get_noncrypt_random_bytes(
                random.randint(min_size, max_size))

        with TemporaryDirectory() as tds:
            temp_dir = Path(tds)
            sf = write_salt_and_fakes(Path(tds))
            self.assertIsInstance(sf.salt, bytes)
            self.assertEqual(len(sf.salt), PK_SALT_SIZE)

            # writing a lot of small files with wrong names
            # for _ in range(50):
            #     bn = bytes_to_fn_str(get_noncrypt_random_bytes(2))
            #     assert not looks_like_our_basename(bn)
            #     (temp_dir / bn).write_bytes(
            #         random_file_content(0, MAX_SALT_FILE_SIZE))

            # writing a lot of large files with correct names
            for _ in range(50):
                data = random_file_content(MAX_SALT_FILE_SIZE + 1,
                                           MAX_SALT_FILE_SIZE + 1000)
                unique_filename(temp_dir).write_bytes(data)

            found_again = find_salt_in_dir(temp_dir)
            self.assertEqual(found_again, sf.salt)

            # salts = list(iter_salts_in_dir(td))

        # self.assertEqual(len(salts), 1)
        # salt = salts[0]
        # self.assertIsInstance(salt, bytes)
        # self.assertEqual(len(salt), PK_SALT_SIZE)


if __name__ == "__main__":
    unittest.main()
