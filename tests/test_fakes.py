# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import datetime
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List, Set

from codn.cryptodir._10_kdf import FasterKDF, FilesetPrivateKey
from codn.cryptodir.namegroup.fakes import create_fake
from codn.cryptodir.namegroup.encdec._25_encdec_part import is_file_from_namegroup
from codn.cryptodir.namegroup.navigator import NewNameGroup
from tests.common import testing_salt


def name_group_to_content_files(ng: NewNameGroup) -> List[Path]:
    return [gf.path for gf in ng.files if gf.is_fresh_data]


def unique_strings(items: List) -> Set[str]:
    return set(str(x) for x in items)


class TestFileWithFakes(unittest.TestCase):
    faster: FasterKDF

    @classmethod
    def setUpClass(cls) -> None:
        cls.faster = FasterKDF()
        cls.faster.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.faster.end()

    def test_create_fakes(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            N = 10
            pk = FilesetPrivateKey('abc', testing_salt)
            for _ in range(N):
                fake_file = create_fake(pk, 2000, td)
                # self.assertTrue(is_file_from_group(pk, fake_file))

            # check we really created 10 files with unique names
            files = list(td.glob('*'))
            self.assertEqual(len(files), N)

            # check each encoded name matches source name
            for f in files:
                self.assertTrue(is_file_from_namegroup(pk, f))
                self.assertEqual(f.stat().st_size, 2000)

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
                                   days=365.2425 * 8))


if __name__ == "__main__":
    unittest.main()
