# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import datetime
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ksf._00_common import MIN_DATA_FILE_SIZE
from ksf._00_randoms import get_noncrypt_random_bytes
from ksf._20_kdf import FasterKeys, FilesetPrivateKey
from ksf._40_imprint import pk_matches_codename
from ksf._50_sur import create_fake
from ksf._61_encryption import encrypt_to_dir, _DecryptedFile
from ksf._70_navigator import Fileset, update_fileset
from tests.common import testing_salt


class TestFileWithFakes(unittest.TestCase):
    faster: FasterKeys

    @classmethod
    def setUpClass(cls) -> None:
        cls.faster = FasterKeys()
        cls.faster.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.faster.end()

    def test_create_sur(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            N = 10
            pk = FilesetPrivateKey('abc', testing_salt)
            for _ in range(N):
                create_fake(pk, 2000, td)

            # check we really created 10 files with unique names
            files = list(td.glob('*'))
            self.assertEqual(len(files), N)

            # check each encoded name matches source name
            for f in files:
                self.assertTrue(pk_matches_codename(pk, f.name))

            # # check sizes are mostly different
            # sizes = set(f.stat().st_size for f in files)
            # self.assertGreater(len(sizes), 5)

            lm_days = [datetime.date.fromtimestamp(f.stat().st_mtime)
                       for f in files]
            # last-modified days are different
            self.assertGreater(len(set(lm_days)), 5)
            # oldest file is older than month
            self.assertLess(min(lm_days),
                            datetime.date.today() - datetime.timedelta(days=30))

            # newest file is newer than 8 years
            self.assertGreater(max(lm_days),
                               datetime.date.today() - datetime.timedelta(
                               days=365.2425*8))

    def test_find(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)
            source_file = td / "source"
            source_file.write_bytes(bytes([77, 88, 99]))

            NAME = "abc"
            pk = FilesetPrivateKey(NAME, testing_salt)
            for _ in range(5):
                create_fake(pk, 2000, td)
            real = encrypt_to_dir(source_file, pk, td)

            correct = Fileset(td, pk)
            # we have 7 files total (including the source)
            self.assertEqual(sum(1 for _ in td.glob('*')), 7)
            # 6 files corresponding to the name
            self.assertEqual(len(correct.all_files), 6)
            # 5 surrogate files
            self.assertEqual(len(correct.surrogates), 5)
            # one real file
            self.assertEqual(correct.real_file, real)

            incorrect = Fileset(td, FilesetPrivateKey("incorrect name", testing_salt))
            self.assertEqual(len(incorrect.all_files), 0)
            self.assertEqual(incorrect.real_file, None)

    def test_write_with_surrogates_sizes(self):
        # random.seed(9, version=2)

        unique_sizes = set()
        with TemporaryDirectory() as tds:
            td = Path(tds)
            fpk_a = FilesetPrivateKey("some name", testing_salt)
            for _ in range(8):
                source_file_a = td / "a"
                source_file_a.write_bytes(b'abcdef')
                update_fileset(source_file_a, fpk_a, td)
                unique_sizes.update(f.stat().st_size for f in td.glob('*'))

        self.assertGreater(len(unique_sizes), 5)
        #self.assertTrue(all(x >= MIN_DATA_FILE_SIZE for x in unique_sizes))

    def test_write_with_surrogates(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            fpk_a = FilesetPrivateKey("some name", testing_salt)
            fpk_b = FilesetPrivateKey("other name", testing_salt)
            fas = Fileset(td, fpk_a)
            self.assertEqual(len(fas.all_files), 0)

            for _ in range(32):
                the_data_a = get_noncrypt_random_bytes(100)
                source_file_a = td / "a"
                source_file_a.write_bytes(the_data_a)

                the_data_b = get_noncrypt_random_bytes(50)
                source_file_b = td / "b"
                source_file_b.write_bytes(the_data_b)

                # rewriting two filesets at once
                update_fileset(source_file_a, fpk_a, td)
                update_fileset(source_file_b, fpk_b, td)

                # finding the latest file and checking it has the new contents
                fas = Fileset(td, fpk_b)
                self.assertGreaterEqual(len(fas.all_files), 2)
                self.assertEqual(_DecryptedFile(fas.real_file, fpk_b).data,
                                 the_data_b)

                # finding the latest file and checking it has the new contents
                fas = Fileset(td, fpk_a)
                self.assertGreaterEqual(len(fas.all_files), 2)
                self.assertEqual(_DecryptedFile(fas.real_file, fpk_a).data,
                                 the_data_a)
