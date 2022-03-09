# SPDX-FileCopyrightText: (c) 2022 Artёm IG <github.com/rtmigo>
# SPDX-License-Identifier: MIT

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from dmk.a_utils.dirty_file import WritingToTempFile


class TestDirtyFiles(unittest.TestCase):
    def test_write_and_replace(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            def files_count():
                return len(list(td.rglob("*")))

            self.assertEqual(files_count(), 0)

            target = td / "file.txt"

            with WritingToTempFile(target) as wttf:
                self.assertEqual(files_count(), 0)
                wttf.dirty.write_text("content!")
                self.assertEqual(files_count(), 1)
                wttf.replace()

            self.assertEqual(files_count(), 1)
            self.assertEqual(target.read_text(), "content!")

    def test_write_but_no_replace(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            def files_count():
                return len(list(td.rglob("*")))

            self.assertEqual(files_count(), 0)

            target = td / "file.txt"

            class StubError(Exception):
                pass

            try:
                with WritingToTempFile(target) as wttf:
                    self.assertEqual(files_count(), 0)
                    wttf.dirty.write_text("content!")
                    self.assertEqual(files_count(), 1)
                    raise StubError
            except StubError:
                pass

            # we removed the temporary file and did not write to the target

            self.assertEqual(files_count(), 0)

    def test_error_after_replace(self):
        with TemporaryDirectory() as tds:
            td = Path(tds)

            def files_count():
                return len(list(td.rglob("*")))

            self.assertEqual(files_count(), 0)

            target = td / "file.txt"

            class StubError(Exception):
                pass

            try:
                with WritingToTempFile(target) as wttf:
                    self.assertEqual(files_count(), 0)
                    wttf.dirty.write_text("content!")
                    self.assertEqual(files_count(), 1)
                    wttf.replace()  # !!!
                    raise StubError
            except StubError:
                pass

            # we removed the temporary file, but kept the written data
            self.assertEqual(files_count(), 1)
            self.assertEqual(target.read_text(), "content!")
