# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import unittest

from ksf.cryptodir.fileset.random_sizes import random_size_like_others_in_dir, \
    random_size_like_file, random_size_like_file_greater


class TestRandomSizes(unittest.TestCase):
    def test_like_dir_returns_none(self):
        # must return none if not enough unique items
        self.assertIsNone(random_size_like_others_in_dir([]))
        self.assertIsNone(random_size_like_others_in_dir([3]))
        self.assertIsNone(random_size_like_others_in_dir([3, 3, 3, 3]))

    def test_like_dir(self):
        src = [10000, 11000, 8000]
        all_values = set()
        for _ in range(100):
            s = random_size_like_others_in_dir(src)
            self.assertGreater(s, 5000)
            self.assertLess(s, 13000)
            all_values.add(s)
        self.assertGreater(len(all_values), 50)

    def test_like_file(self):
        all_values = set()
        for _ in range(100):
            s = random_size_like_file(10000)
            self.assertGreater(s, 4000)
            self.assertLess(s, 16000)
            all_values.add(s)
        self.assertGreater(len(all_values), 50)

    def test_like_file_greater(self):
        all_values = set()
        for _ in range(100):
            s = random_size_like_file_greater(10000)
            self.assertGreater(s, 10000)
            self.assertLess(s, 16000)
            all_values.add(s)
        self.assertGreater(len(all_values), 50)

    def test_like_file_at_least_kb(self):
        unique_values = set()
        for _ in range(100):
            s = random_size_like_file(5)
            self.assertGreaterEqual(s, 1024)
            unique_values.add(s)
        self.assertGreater(len(unique_values), 3)

    def test_like_file_greater_at_least_kb(self):
        unique_values = set()
        for _ in range(100):
            s = random_size_like_file_greater(5)
            self.assertGreaterEqual(s, 1024)
            unique_values.add(s)
        self.assertGreater(len(unique_values), 3)

    def test_like_dir_at_least_kb(self):
        src = [50, 10, 800]
        unique_values = set()
        for _ in range(100):
            s = random_size_like_others_in_dir(src)
            self.assertGreaterEqual(s, 1024)
            unique_values.add(s)
        self.assertGreater(len(unique_values), 3)


if __name__ == "__main__":
    unittest.main()
