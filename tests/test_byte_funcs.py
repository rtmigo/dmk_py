# SPDX-FileCopyrightText: (c) 2021 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT


import unittest

from dmk.b_cryptoblobs._10_byte_funcs import uint16_to_bytes, \
    bytes_to_uint16


class Test(unittest.TestCase):
    def test_uint16(self):
        self.assertEqual(bytes_to_uint16(uint16_to_bytes(777)), 777)
        uint16_to_bytes(0xFFFF)  # ok
        with self.assertRaises(OverflowError):
            uint16_to_bytes(0xFFFF + 1)
        with self.assertRaises(OverflowError):
            uint16_to_bytes(-1)
