# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import unittest

from dmk.a_base._10_kdf import CodenameKey
from tests.common import testing_salt


class TestKdf(unittest.TestCase):

    # @unittest.skip('tmp')
    def test_constant(self):
        assert CodenameKey.is_standard_params()
        # assert CodenameKey.get_params().time >= 4

        KEY_FROM_PASSWORD = (
            177, 226, 27, 41, 236, 37, 217, 101, 245, 101, 204, 244, 254, 205,
            254, 208, 135, 173, 69, 212, 61, 168, 35, 53, 131, 68, 55, 91, 16,
            66, 69, 210)

        KEY_FROM_OTHER = (
            82, 129, 100, 91, 179, 52, 100, 160, 168, 206, 98, 192, 159, 217,
            187, 184, 178, 181, 138, 45, 170, 47, 28, 184, 215, 247, 194, 75,
            231, 252, 121, 33)

        h = CodenameKey('password', testing_salt).as_bytes
        self.assertEqual(h, bytes(KEY_FROM_PASSWORD),
                         list(h))

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
