# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import datetime
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ksf._00_randoms import get_fast_random_bytes
from ksf._20_key_derivation import FasterKeys
from ksf._40_imprint import name_matches_encoded
from ksf._50_sur import create_surrogate
from ksf._61_encryption import encrypt_to_dir, DecryptedFile
from ksf._70_navigator import FileAndSurrogates, write_with_surrogates


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
            for _ in range(N):
                create_surrogate('abc', 2000, td)

            # check we really created 10 files with unique names
            files = list(td.glob('*'))
            self.assertEqual(len(files), N)

            # check each encoded name matches source name
            for f in files:
                self.assertTrue(name_matches_encoded('abc', f.name))

            # check sizes are mostly different
            sizes = set(f.stat().st_size for f in files)
            self.assertGreater(len(sizes), 5)

            lm_days = [datetime.date.fromtimestamp(f.stat().st_mtime)
                       for f in files]
            # last-modified days are different
            self.assertGreater(len(set(lm_days)), 5)
            # oldest file is older than month
            self.assertLess(min(lm_days),
                            datetime.date.today() - datetime.timedelta(days=30))

            # newest file is newer than 11 months
            self.assertGreater(max(lm_days),
                               datetime.date.today() - datetime.timedelta(
                                   days=30 * 11))

    def test_find(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)
            source_file = td / "source"
            source_file.write_bytes(bytes([77, 88, 99]))

            NAME = "abc"
            for _ in range(5):
                create_surrogate(NAME, 2000, td)
            real = encrypt_to_dir(source_file, NAME, td)

            correct = FileAndSurrogates(td, NAME)
            # we have 7 files total (including the source)
            self.assertEqual(sum(1 for _ in td.glob('*')), 7)
            # 6 files corresponding to the name
            self.assertEqual(len(correct.all_files), 6)
            # 5 surrogate files
            self.assertEqual(len(correct.surrogates), 5)
            # one real file
            self.assertEqual(correct.real_file, real)

            incorrect = FileAndSurrogates(td, "incorrect name")
            self.assertEqual(len(incorrect.all_files), 0)
            self.assertEqual(incorrect.real_file, None)

    def test_write_with_surrogates(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            NAME = "abc"
            fas = FileAndSurrogates(td, NAME)
            self.assertEqual(len(fas.all_files), 0)

            # todo in windows this test probably needs two-seconds pause

            for _ in range(10):
                the_data = get_fast_random_bytes(100)

                source_file = td / "source"
                source_file.write_bytes(the_data)

                write_with_surrogates(source_file, NAME, td)

                # finding the latest file and checking it has the new contents
                fas = FileAndSurrogates(td, NAME)
                self.assertGreaterEqual(len(fas.all_files), 2)
                self.assertEqual(DecryptedFile(fas.real_file, NAME).data,
                                 the_data)
