# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import unittest
from io import BytesIO

from ksf._20_encryption import IntroPadding


class TestEncryptDecrypt(unittest.TestCase):

    def test_min_len_1(self):
        self.assertEqual(
            min(len(IntroPadding.gen_bytes()) for _ in range(200)),
            1)

    def test_max_len_15(self):
        self.assertEqual(
            max(len(IntroPadding.gen_bytes()) for _ in range(200)),
            15)

    def test_skipping(self):
        for _ in range(200):
            with BytesIO() as data:
                # writing padding, then marker data
                data.write(IntroPadding.gen_bytes())
                data.write(bytes([17, 23]))

                # moving to the beginning and skipping the padding
                data.seek(0)
                IntroPadding.skip_in_file(data)

                # check we are exactly at marker
                self.assertEqual(tuple(data.read(2)), (17, 23))
