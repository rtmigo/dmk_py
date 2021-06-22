# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT
import random
import unittest

from dmk._common import CODENAME_LENGTH_BYTES
from dmk.a_utils.randoms import get_noncrypt_random_bytes, random_codename_fullsize


class TestRandomBytes(unittest.TestCase):

    def test_len(self):
        self.assertEqual(len(get_noncrypt_random_bytes(16)), 16)
        self.assertEqual(len(get_noncrypt_random_bytes(10)), 10)
        self.assertEqual(len(get_noncrypt_random_bytes(0)), 0)

    def test_len_many(self):
        for _ in range(100):
            n = random.randint(0, 20000)
            self.assertEqual(len(get_noncrypt_random_bytes(n)), n)

    def test_type(self):
        self.assertIsInstance(get_noncrypt_random_bytes(16), bytes)

    def test_is_different(self):
        self.assertNotEqual(
            get_noncrypt_random_bytes(50),
            get_noncrypt_random_bytes(50))

    def test_random_ascii_keys_different(self):
        self.assertNotEqual(
            random_codename_fullsize(),
            random_codename_fullsize()
        )

    def test_random_ascii_keys(self):
        a = random_codename_fullsize()
        self.assertEqual(len(a), CODENAME_LENGTH_BYTES)
        _ = a.encode('ascii')
