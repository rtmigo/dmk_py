# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import datetime
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ksf._40_imprint import name_matches_encoded
from ksf._50_fakes import create_fake
from ksf._51_encryption import encrypt_to_dir
from ksf._60_file_with_fakes import FileAndFakes


class TestFileWithFakes(unittest.TestCase):

    def test_create_fakes(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            N = 10
            for _ in range(N):
                create_fake('abc', 2000, td)

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

    def test_find_file_and_fakes(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)
            source_file = td / "source"
            source_file.write_bytes(bytes([77, 88, 99]))

            NAME = "abc"
            for _ in range(5):
                create_fake(NAME, 2000, td)
            real = encrypt_to_dir(source_file, NAME, td)

            correct = FileAndFakes(td, NAME)
            # we have 7 files total (including the source)
            self.assertEqual(sum(1 for _ in td.glob('*')), 7)
            # 6 files corresponding to the name
            self.assertEqual(len(correct.all_files), 6)
            # one real file
            self.assertEqual(correct.file, real)

            incorrect = FileAndFakes(td, "incorrect name")
            self.assertEqual(len(incorrect.all_files), 0)
            self.assertEqual(incorrect.file, None)
