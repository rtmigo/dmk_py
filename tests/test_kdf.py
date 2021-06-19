# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import unittest

from dmk.a_base._10_kdf import CodenameKey
from tests.common import testing_salt


class TestKdf(unittest.TestCase):

    # @unittest.skip('tmp')
    def test_constant(self):
        assert CodenameKey.is_standard_params()
        #assert CodenameKey.get_params().time >= 4

        KEY_FROM_PASSWORD = (
            192, 116, 209, 12, 247, 121, 244, 135, 101, 77, 121, 138, 253, 37,
            11, 214, 50, 183, 175, 9, 218, 230, 218, 219, 132, 110, 175, 225,
            253, 184, 84, 173)

        KEY_FROM_OTHER = (
            19, 79, 133, 222, 232, 108, 200, 196, 196, 200, 180, 151, 82, 38,
            176, 0, 108, 252, 219, 253, 86, 115, 228, 184, 37, 187, 19, 111,
            205, 200, 174, 246)

        # print(list(CodenameKey('password', testing_salt).as_bytes))
        # print(list(CodenameKey('other', testing_salt).as_bytes))
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
        old_params = CodenameKey.get_params()
        # POWER = CodenameKey._time_cost
        p = CodenameKey(PWD, testing_salt)
        self.assertNotIn(p.as_bytes, seen)
        seen.add(p.as_bytes)
        self.assertIn(p.as_bytes, seen)

        # different password
        p = CodenameKey("other password", testing_salt)
        self.assertNotIn(p.as_bytes, seen)
        seen.add(p.as_bytes)

        with self.subTest("Different time cost"):
            try:
                CodenameKey.set_params(time_cost=old_params.time - 1,
                                       mem_cost=old_params.mem)  # -= 1
                p = CodenameKey(PWD, testing_salt)
                self.assertNotIn(p.as_bytes, seen)
                seen.add(p.as_bytes)

            finally:
                CodenameKey.set_params(time_cost=old_params.time,
                                       mem_cost=old_params.mem)

        with self.subTest("Different mem cost"):
            try:
                CodenameKey.set_params(time_cost=old_params.time,
                                       mem_cost=old_params.mem*2)  # -= 1
                p = CodenameKey(PWD, testing_salt)
                self.assertNotIn(p.as_bytes, seen)
                seen.add(p.as_bytes)

            finally:
                CodenameKey.set_params(time_cost=old_params.time,
                                       mem_cost=old_params.mem)

        self.assertEqual(len(seen), 4)


if __name__ == "__main__":
    unittest.main()
