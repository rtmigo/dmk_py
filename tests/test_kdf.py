# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import unittest

from dmk.a_base._10_kdf import CodenameKey
from tests.common import testing_salt


class TestKdf(unittest.TestCase):

    # @unittest.skip('tmp')
    def test_constant_1(self):
        assert CodenameKey.is_standard_params()

        KEY_FROM_PASSWORD = (
            183, 187, 207, 11, 154, 216, 190, 216, 237, 63, 1, 105, 206, 179, 193, 126, 205, 104, 128, 203, 218, 134, 191, 182, 184, 206, 119, 255, 23, 97, 60, 57)


        h = CodenameKey('password', testing_salt).as_bytes
        self.assertEqual(h, bytes(KEY_FROM_PASSWORD),
                         list(h))

    def test_constant_2(self):
        KEY_FROM_OTHER = (
            194, 20, 66, 1, 71, 124, 174, 228, 149, 209, 187, 97, 198, 136, 12, 198, 134, 51, 110, 91, 7, 220, 32, 107, 81, 139, 129, 204, 242, 111, 11, 184)

        h = CodenameKey('other', testing_salt).as_bytes
        self.assertEqual(h, bytes(KEY_FROM_OTHER),
                         list(h))


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
                                       mem_cost=old_params.mem * 2)  # -= 1
                p = CodenameKey(PWD, testing_salt)
                self.assertNotIn(p.as_bytes, seen)
                seen.add(p.as_bytes)

            finally:
                CodenameKey.set_params(time_cost=old_params.time,
                                       mem_cost=old_params.mem)

        self.assertEqual(len(seen), 4)


if __name__ == "__main__":
    unittest.main()
