# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import unittest

from dmk.a_base._10_kdf import CodenameKey
from tests.common import testing_salt


class TestKdf(unittest.TestCase):

    #@unittest.skip('tmp')
    def test_constant(self):
        assert CodenameKey._time_cost >= 3

        KEY_FROM_PASSWORD = (
            135, 185, 64, 145, 53, 127, 53, 240, 132, 7, 190, 164, 41, 21, 140,
            235, 111, 141, 89, 100, 68, 75, 59, 72, 230, 58, 252, 209, 87, 75,
            244, 252)

        KEY_FROM_OTHER = (
            208, 147, 48, 82, 118, 126, 16, 33, 255, 71, 226, 74, 120, 172,
            196, 34, 3, 30, 19, 32, 19, 62, 70, 156, 63, 75, 7, 133, 183, 246,
            23, 67)

        #print(list(CodenameKey('password', testing_salt).as_bytes))
        #print(list(CodenameKey('other', testing_salt).as_bytes))
        self.assertEqual(CodenameKey('password', testing_salt).as_bytes,
                         bytes(KEY_FROM_PASSWORD))

        self.assertEqual(CodenameKey('other', testing_salt).as_bytes,
                         bytes(KEY_FROM_OTHER))

        # self.assertEqual(len(FilesetPrivateKey.salt), 32)

    # def test_salt_len(self):
    #     self.assertEqual(len(FilesetPrivateKey.salt), 32)

    def test_key_len(self):
        self.assertEqual(len(CodenameKey('pass', testing_salt).as_bytes), 32)

    def test_keys_are_different(self):
        self.assertNotEqual(CodenameKey('abc', testing_salt).as_bytes,
                            CodenameKey('d', testing_salt).as_bytes)

    def test(self):
        # the password to key returns cached values, so we
        # test two things at once:
        # * that all the parameter changes lead to different keys
        # * that cache keys are unique

        seen = set()

        PWD = "password"
        POWER = CodenameKey._time_cost
        p = CodenameKey(PWD, testing_salt)
        self.assertNotIn(p.as_bytes, seen)
        seen.add(p.as_bytes)
        self.assertIn(p.as_bytes, seen)

        # different password
        p = CodenameKey("other password", testing_salt)
        self.assertNotIn(p.as_bytes, seen)
        seen.add(p.as_bytes)

        # different power
        try:
            CodenameKey._time_cost -= 1

            # different power
            p = CodenameKey(PWD, testing_salt)
            self.assertNotIn(p.as_bytes, seen)
            seen.add(p.as_bytes)

        finally:
            CodenameKey._power = POWER

        self.assertEqual(len(seen), 3)


if __name__ == "__main__":
    unittest.main()
