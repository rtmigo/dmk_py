# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import unittest
from difflib import SequenceMatcher

from ksf._20_key_derivation import FasterKeys, FilesetPrivateKey
from ksf._40_imprint import bytes_to_str, str_to_bytes, \
    pk_matches_codename, Imprint, pk_matches_imprint_bytes


def lccs(a, b):
    # finds the longest common contiguous subsequence
    # https://stackoverflow.com/a/39404777
    return SequenceMatcher(None, a, b) \
        .find_longest_match(0, len(a), 0, len(b)) \
        .size

    # return max(len(ss) for ss in find_common_subsequences(a, b))


# assert lccs('abc123def', 'qweqwe123zz') == 3
# assert lccs('abc123def', 'qweqwe1x2x3zz') == 1
#
# print(lccs('abc123def', 'qweqwe123zz'))
# exit()


class Test(unittest.TestCase):
    # todo test the pk and the imprint does n

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

    def test_key_not_in_imprint(self):
        pk = FilesetPrivateKey("pass")
        imp = Imprint(pk)

        self.assertLess(lccs(pk.as_bytes, imp.as_bytes), 4)

    def test_bytes_to_nonce(self):
        pk = FilesetPrivateKey("pass")
        imp = Imprint(pk)

        self.assertIsInstance(imp.nonce, bytes)
        self.assertEqual(len(imp.nonce), 24)

        self.assertEqual(imp.bytes_to_nonce(imp.as_bytes), imp.nonce)

    def test_match_codename(self):
        name = 'abc.txt'
        pk = FilesetPrivateKey(name)
        encoded = Imprint(pk).as_str

        self.assertTrue(
            pk_matches_codename(pk, encoded))
        self.assertFalse(
            pk_matches_codename(FilesetPrivateKey('other.txt'), encoded))
        self.assertFalse(
            pk_matches_codename(FilesetPrivateKey('another.txt'), encoded))

    def test_match_bytes(self):
        name = 'abc.txt'
        pk = FilesetPrivateKey(name)
        imp_bytes = Imprint(pk).as_bytes

        self.assertTrue(pk_matches_imprint_bytes(pk, imp_bytes))
        self.assertFalse(
            pk_matches_imprint_bytes(FilesetPrivateKey('other.txt'), imp_bytes))
        self.assertFalse(
            pk_matches_imprint_bytes(FilesetPrivateKey('another.txt'), imp_bytes))

    def test_imporint_string_not_too_long(self):
        with FasterKeys():
            for i in range(50):
                name = f'abc{i}.txt'
                pk = FilesetPrivateKey(name)
                self.assertLess(len(Imprint(pk).as_str), 65)

    def test_encode_each_time_different(self):
        pk = FilesetPrivateKey('the_same_key')
        with FasterKeys():
            s = set()
            for _ in range(10):
                s.add(Imprint(pk).as_str)
            self.assertEqual(len(s), 10)

    def test_hash_each_time_different(self):
        with FasterKeys():
            s = set()
            pk = FilesetPrivateKey('the_same_key')
            for _ in range(10):
                s.add(Imprint(pk).as_bytes)
            self.assertEqual(len(s), 10)


if __name__ == "__main__":
    unittest.main()
