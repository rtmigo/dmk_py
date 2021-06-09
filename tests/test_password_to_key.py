# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import unittest

from ksf._20_key_derivation import password_to_key, KeyDerivationSettings


class TestPtk(unittest.TestCase):

    def test(self):
        # the password to key returns cached values, so we
        # test two things at once:
        # * that all the parameter changes lead to different keys
        # * that cache keys are unique

        seen = set()

        PWD = "password"
        SALT = bytes([1, 2, 3])
        POWER = KeyDerivationSettings.power
        KL = 24

        p = password_to_key(PWD, SALT, KL)
        self.assertNotIn(p, seen)
        seen.add(p)

        # different password
        p = password_to_key("other password", SALT, KL)
        self.assertNotIn(p, seen)
        seen.add(p)

        # different salt
        p = password_to_key(PWD, bytes([99, 88, 77]), KL)
        self.assertNotIn(p, seen)
        seen.add(p)

        # different key length
        p = password_to_key(PWD, SALT, 16)
        self.assertNotIn(p, seen)
        seen.add(p)

        try:
            KeyDerivationSettings.power -= 1

            # different power
            p = password_to_key(PWD, SALT, KL)
            self.assertNotIn(p, seen)
            seen.add(p)

        finally:
            KeyDerivationSettings.power = POWER

        self.assertEqual(len(seen), 5)

    def test_empty_password(self):
        r = password_to_key('', bytes([1, 2, 3]))
        self.assertIsInstance(r, bytes)

    def test_empty_salt(self):
        r = password_to_key('pass', bytes([]))
        self.assertIsInstance(r, bytes)
