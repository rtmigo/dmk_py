# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import unittest

from dmk.a_utils.randoms import random_basename, looks_like_random_basename


class TestRandomName(unittest.TestCase):
    def test(self):
        names = set(random_basename() for _ in range(100))
        lengths = set(len(n) for n in names)
        self.assertGreater(len(names), 5)
        self.assertGreater(len(lengths), 2)
        self.assertTrue(all(looks_like_random_basename(n) for n in names))

    def test_looks_like(self):
        self.assertTrue(looks_like_random_basename('abc123'))
        self.assertFalse(looks_like_random_basename('Abc123'))
        self.assertFalse(looks_like_random_basename('thumbs.db'))
        self.assertFalse(looks_like_random_basename('.git'))
        self.assertFalse(looks_like_random_basename('build'))  # no digits
        self.assertFalse(looks_like_random_basename('123'))  # no alpha


if __name__ == "__main__":
    unittest.main()
