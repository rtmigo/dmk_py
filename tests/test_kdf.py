# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import unittest

from codn.cryptodir._10_kdf import FilesetPrivateKey
from tests.common import testing_salt


class TestKdf(unittest.TestCase):

    def test_constant(self):
        assert FilesetPrivateKey._power >= 16
        # self.assertEqual(FilesetPrivateKey('password'))
        # self.assertEqual(len(FilesetPrivateKey.salt), 32)

    # def test_salt_len(self):
    #     self.assertEqual(len(FilesetPrivateKey.salt), 32)

    def test_key_len(self):
        self.assertEqual(len(FilesetPrivateKey('pass', testing_salt).as_bytes), 32)

    def test_keys_are_different(self):
        self.assertNotEqual(FilesetPrivateKey('abc', testing_salt).as_bytes,
                            FilesetPrivateKey('d', testing_salt).as_bytes)

    def test(self):
        # the password to key returns cached values, so we
        # test two things at once:
        # * that all the parameter changes lead to different keys
        # * that cache keys are unique

        seen = set()

        PWD = "password"
        POWER = FilesetPrivateKey._power
        p = FilesetPrivateKey(PWD, testing_salt)
        self.assertNotIn(p.as_bytes, seen)
        seen.add(p.as_bytes)
        self.assertIn(p.as_bytes, seen)

        # different password
        p = FilesetPrivateKey("other password", testing_salt)
        self.assertNotIn(p.as_bytes, seen)
        seen.add(p.as_bytes)

        # different power
        try:
            FilesetPrivateKey._power -= 1

            # different power
            p = FilesetPrivateKey(PWD, testing_salt)
            self.assertNotIn(p.as_bytes, seen)
            seen.add(p.as_bytes)

        finally:
            FilesetPrivateKey._power = POWER

        self.assertEqual(len(seen), 3)


if __name__ == "__main__":
    unittest.main()
