# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import unittest
from pathlib import Path

from codn._config import Config


class TestConfig(unittest.TestCase):
    def test(self):
        f = Path(__file__).parent/"data"/"config.ini"
        c = Config(f)
        # the relative path of data file must be resolved to 'data' dir
        self.assertEqual(c.data_dir, Path(__file__).parent / "data" / "cryptodir")
        self.assertTrue(c.data_dir.is_absolute())

        # todo test variables and user expansion
        #assert False

if __name__ == "__main__":
    unittest.main()