# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import random
import unittest
from io import BytesIO

from ksf.cryptodir.fileset._10_padding import IntroPadding


class TestIntro(unittest.TestCase):

    def test_min_len_1(self):
        for maxlen in [2, 8]:
            self.assertEqual(
                min(len(IntroPadding(maxlen).gen_bytes()) for _ in range(1000)),
                1)

    def test_max_len_64(self):
        random.seed(1, version=2)
        self.assertEqual(
            max(len(IntroPadding(64).gen_bytes()) for _ in range(200)),
            64)

    def test_skipping(self):
        for _ in range(200):
            with BytesIO() as data:
                # writing padding, then marker data
                data.write(IntroPadding(64).gen_bytes())
                data.write(bytes([17, 23]))

                # moving to the beginning and skipping the padding
                data.seek(0)
                IntroPadding(64).skip_in_file(data)

                # check we are exactly at marker
                self.assertEqual(tuple(data.read(2)), (17, 23))

    def test_must_be_power_of_two(self):
        IntroPadding(2)
        IntroPadding(4)
        IntroPadding(8)

        with self.assertRaises(ValueError):
            IntroPadding(5)
        with self.assertRaises(ValueError):
            IntroPadding(3)
        with self.assertRaises(ValueError):
            IntroPadding(1)

    def test_must_be_in_correct_range(self):
        with self.assertRaises(ValueError):
            IntroPadding(-2)
        with self.assertRaises(ValueError):
            IntroPadding(0)
        with self.assertRaises(ValueError):
            IntroPadding(1)
        with self.assertRaises(ValueError):
            IntroPadding(512)
