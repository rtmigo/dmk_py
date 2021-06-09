# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import unittest

from ksf._20_key_derivation import FilesetPrivateKey


class TestPtk(unittest.TestCase):

    def test_salt_len(self):
        self.assertEqual(len(FilesetPrivateKey.salt), 32)

    def test_key_len(self):
        self.assertEqual(len(FilesetPrivateKey('pass').as_bytes), 32)

    def test_keys_are_different(self):
        self.assertNotEqual(FilesetPrivateKey('abc').as_bytes,
                            FilesetPrivateKey('d').as_bytes)

    def test(self):
        # the password to key returns cached values, so we
        # test two things at once:
        # * that all the parameter changes lead to different keys
        # * that cache keys are unique

        seen = set()

        PWD = "password"
        POWER = FilesetPrivateKey._power
        p = FilesetPrivateKey(PWD)
        self.assertNotIn(p.as_bytes, seen)
        seen.add(p.as_bytes)
        self.assertIn(p.as_bytes, seen)

        # different password
        p = FilesetPrivateKey("other password")
        self.assertNotIn(p.as_bytes, seen)
        seen.add(p.as_bytes)

        # different power
        try:
            FilesetPrivateKey._power -= 1

            # different power
            p = FilesetPrivateKey(PWD)
            self.assertNotIn(p.as_bytes, seen)
            seen.add(p.as_bytes)

        finally:
            FilesetPrivateKey._power = POWER

        self.assertEqual(len(seen), 3)

    # №        KL = 24
    #
    #     p = password_to_key(PWD, SALT, KL)
    #     self.assertNotIn(p, seen)
    #     seen.add(p)
    #
    #
    #     # different salt
    #     p = password_to_key(PWD, bytes([99, 88, 77]), KL)
    #     self.assertNotIn(p, seen)
    #     seen.add(p)
    #
    #     # different key length
    #     p = password_to_key(PWD, SALT, 16)
    #     self.assertNotIn(p, seen)
    #     seen.add(p)
    #
    #     try:
    #         KdfSettings.power -= 1
    #
    #         # different power
    #         p = password_to_key(PWD, SALT, KL)
    #         self.assertNotIn(p, seen)
    #         seen.add(p)
    #
    #     finally:
    #         KdfSettings.power = POWER
    #
    #     self.assertEqual(len(seen), 5)
    #
    # def test_empty_password(self):
    #     r = password_to_key('', bytes([1, 2, 3]))
    #     self.assertIsInstance(r, bytes)
    #
    # def test_empty_salt(self):
    #     r = password_to_key('pass', bytes([]))
    #     self.assertIsInstance(r, bytes)


if __name__ == "__main__":
    unittest.main()
