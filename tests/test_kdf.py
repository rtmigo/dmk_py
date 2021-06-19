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
            187, 125, 143, 1, 179, 45, 151, 71, 13, 59, 163, 135, 148, 224, 22, 181, 5, 253, 54, 172, 17, 243, 11, 24, 123, 100, 19, 95, 86, 107, 239, 129)

        KEY_FROM_OTHER = (
            197, 53, 245, 111, 187, 176, 135, 69, 5, 205, 158, 125, 245, 147,
            90, 147, 20, 145, 15, 59, 158, 193, 250, 102, 168, 129, 146, 147,
            229, 126, 72, 90)

        print(list(CodenameKey('password', testing_salt).as_bytes))
        #print(list(CodenameKey('other', testing_salt).as_bytes))
        self.assertEqual(CodenameKey('password', testing_salt).as_bytes,
                         bytes(KEY_FROM_PASSWORD))

        # self.assertEqual(CodenameKey('other', testing_salt).as_bytes,
        #                  bytes(KEY_FROM_OTHER))

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
