# SPDX-FileCopyrightText: (c) 2022 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from dmk import DmkFile, get_text, set_text, DmkKeyError, set_file, get_file


class TestOps(unittest.TestCase):

    def test_get_set_text(self):
        with TemporaryDirectory() as tds:
            dmk_file = DmkFile(Path(tds) / "dmk")

            with self.subTest("DmkKeyError"):
                with self.assertRaises(DmkKeyError):
                    get_text(dmk_file, "alpha")
                with self.assertRaises(DmkKeyError):
                    get_text(dmk_file, "beta")

            with self.subTest("Set and read"):
                set_text(dmk_file, "alpha", "value_a")
                set_text(dmk_file, "beta", "value_b")
                self.assertEqual(
                    "value_a",
                    get_text(dmk_file, "alpha"))
                self.assertEqual(
                    "value_b",
                    get_text(dmk_file, "beta"))

    def test_get_set_from_file(self):
        with TemporaryDirectory() as tds:
            tempdir = Path(tds)
            dmk_file = DmkFile(Path(tempdir) / "dmk")

            with self.subTest("When keys does not exist"):
                stub = tempdir/"stub"
                self.assertFalse(stub.exists())
                with self.assertRaises(DmkKeyError):
                    get_file(dmk_file, "alpha", stub)
                with self.assertRaises(DmkKeyError):
                    get_file(dmk_file, "beta", stub)
                # we did not create the file, since the keys were not
                # found
                self.assertFalse(stub.exists())

            src_a = tempdir / "src_a"
            src_b = tempdir / "src_b"

            src_a.write_text("value_a")
            src_b.write_text("value_b")

            dst_a = tempdir / "dst_a"
            dst_b = tempdir / "dst_b"

            with self.subTest("Set files, get files"):
                set_file(dmk_file, "alpha", src_a)
                set_file(dmk_file, "beta", src_b)

                get_file(dmk_file, "alpha", dst_a)
                get_file(dmk_file, "beta", dst_b)

                self.assertEqual(
                    dst_b.read_bytes(),
                    src_b.read_bytes())
                self.assertEqual(
                    dst_a.read_bytes(),
                    src_a.read_bytes())

                # self-check:
                self.assertNotEqual(
                    dst_a.read_bytes(),
                    src_b.read_bytes())

            with self.subTest("Will not overwrite when reading"):
                with self.assertRaises(FileExistsError):
                    get_file(dmk_file, "alpha", dst_b)
                # it holds old value
                self.assertEqual(
                    "value_a",
                    get_text(dmk_file, "alpha"))

            with self.subTest("Will not set from file that does not exist"):
                unexisting = tempdir / "unexisting"
                assert not unexisting.exists()

                with self.assertRaises(FileNotFoundError):
                    set_file(dmk_file, "zzz", unexisting)
                # we did not set
                self.assertIsNone(dmk_file.get_bytes("zzz"))
