# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import unittest

from ksf._40_imprint import bytes_to_str, str_to_bytes, \
    name_matches_encoded, Imprint
from ksf._20_key_derivation import FasterKeys


class Test(unittest.TestCase):
    faster: FasterKeys

    @classmethod
    def setUpClass(cls) -> None:
        cls.faster = FasterKeys()
        cls.faster.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.faster.end()

    def test_bytes_to_str_to_bytes(self):
        b = bytes([11, 33, 22, 55, 44])
        encoded = bytes_to_str(b)
        self.assertEqual(encoded, 'CyEWNyw=')
        self.assertEqual(str_to_bytes(encoded), b)

    def test_encode_match(self):
        name = 'abc.txt'
        encoded = Imprint(name).as_str
        self.assertNotIn(name, encoded)

        self.assertTrue(name_matches_encoded(name, encoded))
        self.assertFalse(name_matches_encoded('other.txt', encoded))
        self.assertFalse(name_matches_encoded('another.txt', encoded))

    def test_imporint_string_not_too_long(self):
        with FasterKeys():
            for i in range(50):
                name = f'abc{i}.txt'
                self.assertLess(len(Imprint(name).as_str), 65)

    def test_encode_each_time_different(self):
        with FasterKeys():
            s = set()
            for _ in range(10):
                s.add(Imprint('the_same.file').as_str)
            self.assertEqual(len(s), 10)

    def test_hash_each_time_different(self):
        with FasterKeys():
            s = set()
            for _ in range(10):
                s.add(Imprint('the_same.file').as_bytes)
            self.assertEqual(len(s), 10)


if __name__ == "__main__":
    unittest.main()
