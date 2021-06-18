# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import random
import unittest
from io import BytesIO

from dmk.b_cryptoblobs._10_padding import IntroPadding, \
    _set_highest_bit, _is_highest_bit_set, _random_first_byte, \
    _first_byte_to_len


class TestIntro(unittest.TestCase):

    def test_highest_bit(self):
        x = _set_highest_bit(55)
        self.assertEqual(x, 183)
        self.assertTrue(_is_highest_bit_set(x))

        x = _set_highest_bit(56)
        self.assertEqual(x, 184)
        self.assertTrue(_is_highest_bit_set(x))

    def test_first_byte_must_be_step_2(self):

        for _ in range(1000):
            with self.assertRaises(ValueError):
                _first_byte_to_len(_random_first_byte(), 15)
            with self.assertRaises(ValueError):
                _first_byte_to_len(_random_first_byte(), 17)

            # too small and too large
            with self.assertRaises(ValueError):
                _first_byte_to_len(_random_first_byte(), 256)
            with self.assertRaises(ValueError):
                _first_byte_to_len(_random_first_byte(), 1)
            with self.assertRaises(ValueError):
                _first_byte_to_len(_random_first_byte(), 0)

            _first_byte_to_len(_random_first_byte(), 16)
            _first_byte_to_len(_random_first_byte(), 128)

    def test_first_byte(self):
        for max_len in [16, 64, 128]:
            all_lengths = set()
            for i in range(999999):
                first_byte = _random_first_byte()
                length = _first_byte_to_len(first_byte, max_len)
                self.assertEqual(_first_byte_to_len(first_byte, max_len),
                                 length)
                all_lengths.add(length)

                if 0 in all_lengths and max_len-1 in all_lengths and len(
                        all_lengths) > 3:
                    break

            self.assertGreater(len(all_lengths), 3)
            self.assertEqual(min(all_lengths), 0)
            self.assertEqual(max(all_lengths), max_len-1)

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


if __name__ == "__main__":
    unittest.main()
